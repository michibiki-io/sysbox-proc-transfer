/* Exercise the actual helper alive()/guard() functions with real pidfds.
 * EINTR injection is confined to this test translation unit. */
#define _GNU_SOURCE
#include <poll.h>
static int interrupted_poll(struct pollfd *, nfds_t, int);
#define poll interrupted_poll
#define main production_main
#include "../../helper/proc-mount-helper.c"
#undef main
#undef poll
static int interrupted_poll(struct pollfd *p, nfds_t n, int t) {
    static int once;
    if (!once++) {
        errno = EINTR;
        return -1;
    }
    return poll(p, n, t);
}
static void assert_ok(int yes, const char *what) {
    if (!yes) {
        perror(what);
        exit(1);
    }
}
static int probe(int fd) {
    pid_t p = fork();
    assert_ok(p >= 0, "probe fork");
    if (!p) {
        guard();
        if (fd >= 0)
            assert_ok(dup2(fd, 10) == 10, "probe pidfd");
        else
            close(10);
        alive();
        _exit(0);
    }
    int s;
    assert_ok(waitpid(p, &s, 0) == p, "probe wait");
    assert_ok(WIFEXITED(s), "probe exit");
    return WEXITSTATUS(s);
}
int main(void) {
    alarm(30);
    pid_t p = fork();
    assert_ok(p >= 0, "requester fork");
    if (!p) {
        guard();
        pause();
        _exit(0);
    }
    int fd = syscall(SYS_pidfd_open, p, 0x80);
    assert_ok(fd >= 0, "requester thread pidfd");
    assert_ok(probe(fd) == 0, "live requester, retry interrupted poll");
    kill(p, SIGKILL);
    assert_ok(waitpid(p, NULL, 0) == p, "reap requester");
    assert_ok(probe(fd) == ESRCH, "dead requester errno");
    assert_ok(probe(-1) == EBADF, "invalid pidfd errno");
    close(fd);
    /* A worker parent dies: its guarded child must die too. Subreaper lets this
     * test synchronously reap both owned descendants without host changes. */
    assert_ok(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "test subreaper");
    int pipefd[2];
    assert_ok(pipe(pipefd) == 0, "guard readiness");
    p = fork();
    assert_ok(p >= 0, "parent fork");
    if (!p) {
        guard();
        close(pipefd[0]);
        pid_t c = fork();
        if (c < 0)
            _exit(111);
        if (!c) {
            guard();
            assert_ok(write(pipefd[1], "R", 1) == 1, "guard ready");
            pause();
            _exit(111);
        }
        pause();
        _exit(111);
    }
    close(pipefd[1]);
    char c;
    assert_ok(read(pipefd[0], &c, 1) == 1 && c == 'R', "guard checkpoint");
    close(pipefd[0]);
    kill(p, SIGKILL);
    assert_ok(waitpid(p, NULL, 0) == p, "guard parent reap");
    int s;
    assert_ok(waitpid(-1, &s, 0) > 0 && WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL,
              "parent death kills guarded child");
    p = fork();
    assert_ok(p >= 0, "alarm worker");
    if (!p) {
        guard();
        pause();
        _exit(111);
    }
    assert_ok(waitpid(p, &s, 0) == p && WIFSIGNALED(s) && WTERMSIG(s) == SIGALRM,
              "20 second helper alarm");
    puts("PASS helper EINTR, ESRCH, EBADF, parent death and 20 second alarm");
    return 0;
}
