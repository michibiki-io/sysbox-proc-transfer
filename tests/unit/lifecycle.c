#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define THREAD 0x80
static int channel;
static const char *binary;
static void check(int ok, const char *what) {
    if (!ok) {
        perror(what);
        exit(1);
    }
}
static void byte(int fd, char c) { check(write(fd, &c, 1) == 1, "write checkpoint"); }
static char take(int fd) {
    char c;
    check(read(fd, &c, 1) == 1, "read checkpoint");
    return c;
}
static void sendfd(int fd) {
    char data = 'F', control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec i = {&data, 1};
    struct msghdr m = {
        .msg_iov = &i, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fd, sizeof(fd));
    check(sendmsg(channel, &m, 0) == 1, "send listener");
}
static int receive(int s) {
    char d, c[CMSG_SPACE(sizeof(int))];
    struct iovec i = {&d, 1};
    struct msghdr m = {
        .msg_iov = &i, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof(c)};
    check(recvmsg(s, &m, MSG_CMSG_CLOEXEC) == 1, "receive listener");
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    check(h && h->cmsg_type == SCM_RIGHTS, "listener rights");
    int f;
    memcpy(&f, CMSG_DATA(h), sizeof(f));
    return f;
}
static int readable(int fd, int timeout) {
    struct pollfd p = {fd, POLLIN, 0};
    int r;
    do {
        r = poll(&p, 1, timeout);
    } while (r < 0 && errno == EINTR);
    check(r >= 0, "poll");
    return r > 0;
}
static void handler(int s) { (void)s; }
static void *notify(void *unused) {
    (void)unused;
    struct sigaction a = {.sa_handler = handler};
    sigemptyset(&a.sa_mask);
    check(sigaction(SIGUSR1, &a, NULL) == 0, "signal handler");
    struct sock_filter ins[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {sizeof(ins) / sizeof(*ins), ins};
    check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no new privileges");
    int f = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
    check(f >= 0, "new listener");
    sendfd(f);
    close(f);
    errno = 0;
    long r = syscall(SYS_getpid);
    check(r == -1 && errno == EINTR, "notification interrupted");
    byte(channel, 'I');
    char c = take(channel);
    check(c == 'T', "thread exit command");
    return NULL;
}
static void exec_hold(void) {
    check(dup2(channel, 3) == 3, "exec channel");
    check(fcntl(3, F_SETFD, 0) == 0, "inherit exec channel");
    execl(binary, binary, "hold", NULL);
    _exit(111);
}
static void *executor(void *unused) {
    (void)unused;
    check(take(channel) == 'E', "exec command");
    exec_hold();
    return NULL;
}
static void run(int leader, int action) {
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0, "channel");
    pid_t parent = getpid();
    pid_t child = fork();
    check(child >= 0, "fork");
    if (!child) {
        check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent, "fixture parent");
        alarm(20);
        close(pair[0]);
        channel = pair[1];
        pthread_t t;
        if (leader) {
            check(pthread_create(&t, NULL, executor, NULL) == 0, "executor");
            notify(NULL);
            pthread_exit(NULL);
        }
        check(pthread_create(&t, NULL, notify, NULL) == 0, "requester");
        if (action == 2) {
            check(take(channel) == 'E', "exec command");
            exec_hold();
        }
        check(pthread_join(t, NULL) == 0, "join requester");
        byte(channel, 'T');
        pause();
        _exit(0);
    }
    close(pair[1]);
    int listener = receive(pair[0]);
    struct seccomp_notif n = {0};
    check(ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &n) == 0, "receive notification");
    check((n.pid == (uint32_t)child) == leader, "actual notifying TID");
    int thread = syscall(SYS_pidfd_open, n.pid, THREAD),
        process = syscall(SYS_pidfd_open, child, 0);
    check(thread >= 0 && process >= 0, "pidfd acquisition");
    check(!readable(thread, 0) && !readable(process, 0), "initial liveness");
    check(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &n.id) == 0, "valid notification");
    if (action == 0) {
        check(syscall(SYS_tgkill, child, n.pid, SIGUSR1) == 0, "interrupt notifier");
        check(take(pair[0]) == 'I', "interruption ack");
        check(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &n.id) < 0 && errno == ENOENT,
              "actual invalidation");
        check(!readable(thread, 0), "invalidation is not exit");
        struct seccomp_notif_resp r = {.id = n.id};
        check(ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &r) < 0 && errno == ENOENT,
              "no success to invalid notification");
        byte(pair[0], 'T');
        check(take(pair[0]) == 'T', "thread exit ack");
        check(readable(thread, 2000) && !readable(process, 0),
              "thread exit with surviving process");
    }
    if (action == 1) {
        check(kill(child, SIGKILL) == 0, "whole process exit");
        check(readable(thread, 2000) && readable(process, 2000), "whole process pidfds");
        check(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &n.id) < 0 && errno == ENOENT,
              "whole process exit invalidates original notification");
    }
    if (action == 2) {
        byte(pair[0], 'E');
        check(take(pair[0]) == 'X', "exec completed");
        check(ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &n.id) < 0 && errno == ENOENT,
              "exec invalidates original notification");
        check(readable(thread, leader ? 0 : 2000) == !leader,
              "leader replacement versus nonleader exit");
        check(!readable(process, 0), "exec process survives");
    }
    kill(child, SIGKILL);
    check(waitpid(child, NULL, 0) == child, "reap owned process");
    close(listener);
    close(thread);
    close(process);
    close(pair[0]);
    printf("PASS kernel lifecycle leader=%d action=%d\n", leader, action);
}
/* Kernel pidfd_poll delays a prematurely exited leader while its group
 * survives, even for PIDFD_THREAD. Notification validity is a separate check. */
static void *remaining_thread(void *unused) {
    (void)unused;
    byte(channel, 'R');
    pause();
    return NULL;
}
static void leader_exit(void) {
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0, "leader exit channel");
    pid_t parent = getpid();
    pid_t child = fork();
    check(child >= 0, "leader exit fork");
    if (!child) {
        check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent, "leader fixture parent");
        alarm(20);
        close(pair[0]);
        channel = pair[1];
        pthread_t thread;
        check(pthread_create(&thread, NULL, remaining_thread, NULL) == 0, "remaining thread");
        check(take(channel) == 'G', "leader exit release");
        syscall(SYS_exit, 0);
        _exit(111);
    }
    close(pair[1]);
    check(take(pair[0]) == 'R', "remaining thread ready");
    int thread = syscall(SYS_pidfd_open, child, THREAD);
    int process = syscall(SYS_pidfd_open, child, 0);
    check(thread >= 0 && process >= 0, "leader pidfds");
    byte(pair[0], 'G');
    int tr = readable(thread, 2000), pr = readable(process, 0);

    kill(child, SIGKILL);
    check(waitpid(child, NULL, 0) == child, "leader process reaped");
    close(thread);
    close(process);
    close(pair[0]);
    check(!tr && !pr, "leader pidfds defer readiness while group survives");
    puts("PASS kernel leader exit: pidfd readiness delayed while process survives");
}
int main(int argc, char **argv) {
    binary = argv[0];
    alarm(20);
    if (argc == 2 && !strcmp(argv[1], "provide")) {
        channel = 3;
        notify(NULL);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "hold")) {
        byte(3, 'X');
        pause();
        return 0;
    }
    leader_exit();
    run(0, 0);
    run(0, 1);
    run(1, 1);
    run(0, 2);
    run(1, 2);
    return 0;
}
