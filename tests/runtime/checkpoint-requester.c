/* Synthetic notification requester for the trusted direct-helper regression.
 * Its getpid listener is real; actual Sysbox mount coverage is thread-proc.c. */
#define main thread_proc_main
#include "thread-proc.c"
#undef main
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
static const char *control;
static int leader;
static void interrupt_handler(int s) { (void)s; }
static void exec_survivor(void) {
    execl("/bin/sleep", "sleep", "30", NULL);
    _exit(111);
}
static char actor_command(void) {
    char path[2048], c;
    snprintf(path, sizeof(path), "%s/actor", control);
    int fd = open(path, O_RDONLY);
    need(fd >= 0, "actor control");
    need(read(fd, &c, 1) == 1, "actor command");
    close(fd);
    return c;
}
static void *other_thread(void *u) {
    (void)u;
    char c = actor_command();
    if (c == 'E')
        exec_survivor();
    need(c == 'T', "thread exit command");
    return NULL;
}
static void *notifier(void *u) {
    (void)u;
    need(!unshare(CLONE_NEWNS), "distinct requester Mount namespace");
    need(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), "private propagation");
    need(nsino("/proc/thread-self/ns/mnt") != leader_ns, "thread mount namespace differs");
    pid_t observer = fork();
    need(observer >= 0, "surviving observer");
    if (!observer) {
        alarm(40);
        char p[2048];
        snprintf(p, sizeof(p), "%s/observe", control);
        int f = open(p, O_RDONLY);
        need(f >= 0, "observer control");
        char c;
        need(read(f, &c, 1) == 1, "observe command");
        close(f);
        if (c == 'V')
            verify();
        else {
            need(c == 'U', "unchanged command");
            snprintf(p, sizeof(p), "%s/1", target);
            struct stat s;
            need(stat(p, &s) < 0 && errno == ENOENT, "detected failure leaves target unchanged");
            puts("PASS observer target unchanged");
        }
        fflush(stdout);
        _exit(0);
    }
    struct sigaction a = {.sa_handler = interrupt_handler};
    sigemptyset(&a.sa_mask);
    need(!sigaction(SIGUSR1, &a, NULL), "signal handler");
    struct sock_filter ins[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {sizeof(ins) / sizeof(*ins), ins};
    need(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no new privileges");
    int listener =
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
    need(listener >= 0, "notification listener");
    printf("READY %ld %d %d\n", syscall(SYS_gettid), observer, listener);
    fflush(stdout);
    errno = 0;
    long r = syscall(SYS_getpid);
    need(r == -1 && errno == EINTR, "notification interruption");
    puts("INTERRUPTED");
    fflush(stdout);
    {
        char path[2048];
        snprintf(path, sizeof(path), "%s/exit", control);
        int f = open(path, O_RDONLY);
        need(f >= 0, "exit control");
        char c;
        need(read(f, &c, 1) == 1 && c == 'T', "requester thread exit");
        close(f);
        if (leader)
            syscall(SYS_exit, 0);
    }
    return NULL;
}
int main(int argc, char **argv) {
    need(argc == 5, "target control leader/nonleader token");
    alarm(45);
    target = argv[1];
    control = argv[2];
    leader = !strcmp(argv[3], "leader");
    need(leader || !strcmp(argv[3], "nonleader"), "requester mode");
    flags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY;
    need(!mkdir(control, 0700), "control directory");
    need(!mkdir(target, 0700), "target directory");
    char fifo[2048];
    snprintf(fifo, sizeof(fifo), "%s/observe", control);
    need(!mkfifo(fifo, 0600), "observer fifo");
    snprintf(fifo, sizeof(fifo), "%s/exit", control);
    need(!mkfifo(fifo, 0600), "exit fifo");
    snprintf(fifo, sizeof(fifo), "%s/actor", control);
    need(!mkfifo(fifo, 0600), "actor fifo");
    pidns = open("/proc/thread-self/ns/pid", O_RDONLY | O_CLOEXEC);
    need(pidns >= 0, "sandbox PID namespace");
    leader_ns = nsino("/proc/thread-self/ns/mnt");
    capture();
    pthread_t t;
    if (leader) {
        need(!pthread_create(&t, NULL, other_thread, NULL), "exec actor");
        notifier(NULL);
        pthread_join(t, NULL);
    } else {
        need(!pthread_create(&t, NULL, notifier, NULL), "notifier thread");
        need(actor_command() == 'E', "exec actor command");
        exec_survivor();
    }
    return 0;
}
