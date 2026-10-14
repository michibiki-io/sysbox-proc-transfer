/* Run only in a disposable bwrap sandbox in a provisioned Sysbox container.
 * No listener or substitute helper: mount() takes the real Sysbox path. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void need(int ok, const char *s) {
    if (!ok) {
        perror(s);
        exit(1);
    }
}
struct protection {
    char path[1024];
    struct stat st;
    unsigned long flags;
};
static struct protection policy[128];
static int count;
static ino_t leader_ns;
static const char *target;
static int pidns;
static unsigned long flags;
static ino_t nsino(const char *p) {
    struct stat s;
    need(!stat(p, &s), p);
    return s.st_ino;
}
static void capture(void) {
    FILE *f = fopen("/proc/self/mountinfo", "re");
    need(f != NULL, "mountinfo");
    char *line = NULL;
    size_t size = 0;
    while (getline(&line, &size, f) > 0) {
        char path[1024];
        need(sscanf(line, "%*s %*s %*s %*s %1023s", path) == 1, "mountinfo parse");
        if (strncmp(path, "/proc/", 6))
            continue;
        need(!strchr(path, '\\'), "escaped protection path unsupported");
        need(count < 128, "bounded policy");
        struct protection *p = &policy[count++];
        strcpy(p->path, path + 6);
        need(!stat(path, &p->st), "source identity");
        struct statvfs v;
        need(!statvfs(path, &v), "source flags");
        p->flags = v.f_flag;
    }
    free(line);
    fclose(f);
    need(count >= 3, "registered protection mounts");
}
static void verify(void) {
    char p[2048];
    struct stat a, b;
    need(!fstat(pidns, &a), "pinned sandbox pidns");
    snprintf(p, sizeof(p), "%s/1/ns/pid", target);
    need(!stat(p, &b) && a.st_ino == b.st_ino && a.st_dev == b.st_dev, "sandbox PID identity");
    struct statvfs root;
    need(!statvfs(target, &root), "root flags");
    need((root.f_flag & (ST_NOSUID | ST_NODEV | ST_NOEXEC)) == (ST_NOSUID | ST_NODEV | ST_NOEXEC),
         "root security attributes");
    if (flags & MS_RDONLY)
        need(root.f_flag & ST_RDONLY, "readonly root");
    else
        need(!(root.f_flag & ST_RDONLY), "readwrite root");
    for (int i = 0; i < count; i++) {
        struct protection *q = &policy[i];
        snprintf(p, sizeof(p), "%s/%.1023s", target, q->path);
        struct statvfs v;
        need(!stat(p, &b) && !statvfs(p, &v), "target protection");
        need(b.st_dev == q->st.st_dev && b.st_ino == q->st.st_ino,
             "all registered identities retained");
        need(!(q->flags & ST_RDONLY) || (v.f_flag & ST_RDONLY), "readonly retained");
        if (flags & MS_RDONLY)
            need(v.f_flag & ST_RDONLY, "recursive readonly");
        need(umount2(p, MNT_DETACH) < 0, "protected detach denied");
        if (v.f_flag & ST_RDONLY)
            need(mount(NULL, p, NULL, MS_REMOUNT | MS_BIND, NULL) < 0, "readonly clear denied");
    }
    const char *mask[] = {"keys", "interrupts", "timer_list"};
    for (int i = 0; i < 3; i++) {
        snprintf(p, sizeof(p), "%s/%s", target, mask[i]);
        int fd = open(p, O_RDONLY);
        char c;
        need(fd >= 0 && read(fd, &c, 1) == 0, "registered mask retained");
        close(fd);
    }
    puts("PASS surviving observer: sandbox PID, all proc submount identities, readonly, masks, "
         "detach locks");
}
static void *request(void *unused) {
    (void)unused;
    pid_t tid = syscall(SYS_gettid);
    need(tid != getpid(), "TID differs from TGID");
    need(!unshare(CLONE_NEWNS), "thread mount namespace");
    need(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), "private propagation");
    need(nsino("/proc/thread-self/ns/mnt") != leader_ns, "distinct thread mount namespace");
    int pair[2];
    need(!pipe2(pair, O_CLOEXEC), "observer channel");
    pid_t observer = fork();
    need(observer >= 0, "observer fork");
    if (!observer) {
        close(pair[1]);
        char c;
        need(read(pair[0], &c, 1) == 1 && c == 'V', "observer checkpoint");
        verify();
        fflush(stdout);
        _exit(0);
    }
    close(pair[0]);
    need(!mount("proc", target, "proc", flags, NULL), "actual Sysbox nonleader proc mount");
    need(write(pair[1], "V", 1) == 1, "observer release");
    close(pair[1]);
    int status;
    need(waitpid(observer, &status, 0) == observer && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "observer result");
    printf("PASS real Sysbox notifying TID != TGID, distinct Mount namespaces, flags=%lu\n", flags);
    return NULL;
}
int main(int argc, char **argv) {
    need(argc == 3, "target and readonly flag");
    alarm(40);
    target = argv[1];
    flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (!strcmp(argv[2], "readonly"))
        flags |= MS_RDONLY;
    else
        need(!strcmp(argv[2], "readwrite"), "flag mode");
    need(!mkdir(target, 0700), "target");
    pidns = open("/proc/thread-self/ns/pid", O_RDONLY | O_CLOEXEC);
    need(pidns >= 0, "pin sandbox pid namespace");
    leader_ns = nsino("/proc/thread-self/ns/mnt");
    capture();
    pthread_t thread;
    need(!pthread_create(&thread, NULL, request, NULL), "pthread create");
    need(!pthread_join(thread, NULL), "pthread join");
    need(nsino("/proc/thread-self/ns/mnt") == leader_ns, "leader namespace retained");
    char p[2048];
    snprintf(p, sizeof(p), "%s/1", target);
    struct stat s;
    need(stat(p, &s) < 0 && errno == ENOENT, "leader target unchanged");
    close(pidns);
    return 0;
}
