/* Run only in a disposable bwrap sandbox in a provisioned Sysbox container.
 * No listener or substitute helper: mount() takes the real Sysbox path. */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if.h>
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
    int empty_mask;
    int empty_directory;
};
static struct protection policy[128];
static int count;
static ino_t leader_ns;
static const char *target;
static ino_t leader_net;
static int newnet;
static unsigned long flags;
static struct if_nameindex *leader_interfaces;
static const char *private_interface = "issue5-tid";
static void leader_membership(void) {
    struct if_nameindex *now = if_nameindex();
    need(now != NULL, "leader interface membership");
    int before = 0, after = 0;
    for (struct if_nameindex *a = leader_interfaces; a->if_index; a++) {
        before++;
        int found = 0;
        for (struct if_nameindex *b = now; b->if_index; b++)
            if (a->if_index == b->if_index && !strcmp(a->if_name, b->if_name)) found++;
        need(found == 1, "leader interface identity retained");
    }
    for (struct if_nameindex *b = now; b->if_index; b++) after++;
    need(before == after && !if_nametoindex(private_interface), "leader membership unchanged");
    if_freenameindex(now);
}
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
        if (strncmp(path, "/sys/", 5))
            continue;
        need(!strchr(path, '\\'), "escaped protection path unsupported");
        need(count < 128, "bounded policy");
        struct protection *p = &policy[count++];
        strcpy(p->path, path + 5);
        need(!stat(path, &p->st), "source identity");
        struct statvfs v;
        need(!statvfs(path, &v), "source flags");
        p->flags = v.f_flag;
        if (S_ISDIR(p->st.st_mode) && strstr(line," - tmpfs ")) {
            DIR *d=opendir(path);need(d!=NULL,"mask source directory");struct dirent *entry;int entries=0;
            while((entry=readdir(d))) if(strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) entries++;
            closedir(d);p->empty_directory=entries==0;
        }
        if (S_ISCHR(p->st.st_mode)) {
            int fd=open(path,O_RDONLY|O_CLOEXEC);char byte;
            if(fd<0){need(errno==EACCES||errno==EPERM||errno==ENXIO,"capture masked file access policy");p->empty_mask=-1;}
            else {need(read(fd,&byte,1)==0,"capture empty file mask");close(fd);p->empty_mask=1;}
        }
    }
    free(line);
    fclose(f);
    need(count >= 3, "registered protection mounts");
}
static void verify(void) {
    char p[2048];
    struct stat b;
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
        unsigned long floor = q->flags & (ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC);
        if ((v.f_flag & floor) != floor) fprintf(stderr,"floor mismatch %s: expected=%lu actual=%lu\n",q->path,floor,v.f_flag);
        need((v.f_flag & floor) == floor, "all source floors retained");
        need(mount(p, "/tmp", NULL, MS_MOVE, NULL) < 0, "protected move denied");
        if (q->empty_directory) {
            DIR *d=opendir(p);need(d!=NULL,"mask target directory");struct dirent *entry;
            while((entry=readdir(d)))need(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."),"empty directory mask retained");
            closedir(d);
        }
        if (q->empty_mask) {
            int f=open(p,O_RDONLY|O_CLOEXEC);char byte;
            if(q->empty_mask<0)need(f<0&&(errno==EACCES||errno==EPERM||errno==ENXIO),"masked file denial retained");
            else {
                /* The mandatory recursive nodev floor can make a previously
                 * readable /dev/null mask inaccessible. Identity plus EACCES
                 * under nodev preserves hiding; never accept readable data. */
                if(f<0)need(errno==EACCES && (v.f_flag&ST_NODEV),"nodev mask denial retained");
                else need(read(f,&byte,1)==0,"empty mask contents retained");
            }
            if(f>=0)close(f);
        }
        if (S_ISDIR(b.st_mode) && (v.f_flag & ST_RDONLY)) {
            char denied[3072];snprintf(denied,sizeof(denied),"%s/.issue5-write-denied",p);
            need(mkdir(denied,0700)<0 && (errno==EROFS||errno==EACCES||errno==EPERM),"protected RO write denied");
        }
        if (flags & MS_RDONLY)
            need(v.f_flag & ST_RDONLY, "recursive readonly");
        need(umount2(p, MNT_DETACH) < 0, "protected detach denied");
        if (v.f_flag & ST_RDONLY)
            need(mount(NULL, p, NULL, MS_REMOUNT | MS_BIND, NULL) < 0, "readonly clear denied");
    }
    // Compare actual interface names, symlink targets and ifindices with the
    // requester's independent network observation, including raw getdents.
    char cmd[4096];
    need(snprintf(cmd, sizeof(cmd), "/usr/bin/python3 /tmp/issue5-repo/tests/runtime/sysfs-network.py %s", target) < (int)sizeof(cmd), "network command");
    need(system(cmd) == 0, "network view oracle");
    puts("PASS surviving observer: all sysfs source identities, floors, detach locks and network view");
}
static void *request(void *unused) {
    (void)unused;
    pid_t tid = syscall(SYS_gettid);
    need(tid != getpid(), "TID differs from TGID");
    need(!unshare(CLONE_NEWNS | (newnet?CLONE_NEWNET:0)), "thread namespaces");
    if(newnet) {
        need(nsino("/proc/thread-self/ns/net") != leader_net, "distinct thread Network namespace");
        need(!if_nametoindex(private_interface), "private interface initially absent");
        // system's child inherits this actual thread's private Net; CAP_NET_ADMIN
        // belongs only to our mapped child User namespace, never the host.
        need(system("ip link add issue5-tid type dummy") == 0, "private Net dummy creation");
        need(if_nametoindex(private_interface) != 0, "requester-only interface present");
        puts("PASS notifying nonleader private Net contains issue5-tid");
    }
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
    need(!mount("sysfs", target, "sysfs", flags, NULL), "actual Sysbox nonleader sysfs mount");
    need(write(pair[1], "V", 1) == 1, "observer release");
    close(pair[1]);
    int status;
    need(waitpid(observer, &status, 0) == observer && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "observer result");
    printf("PASS real Sysbox notifying TID != TGID, distinct Mount namespaces, flags=%lu\n", flags);
    return NULL;
}
int main(int argc, char **argv) {
    need(argc == 4, "target, readonly flag and network mode");
    newnet=!strcmp(argv[3],"new-net");
    need(newnet||!strcmp(argv[3],"shared-net"),"network mode");
    alarm(40);
    target = argv[1];
    flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (!strcmp(argv[2], "readonly"))
        flags |= MS_RDONLY;
    else
        need(!strcmp(argv[2], "readwrite"), "flag mode");
    need(!mkdir(target, 0700), "target");
    leader_interfaces = if_nameindex();
    need(leader_interfaces != NULL && !if_nametoindex(private_interface), "capture leader membership");
    leader_net=nsino("/proc/thread-self/ns/net");
    leader_ns = nsino("/proc/thread-self/ns/mnt");
    capture();
    pthread_t thread;
    need(!pthread_create(&thread, NULL, request, NULL), "pthread create");
    need(!pthread_join(thread, NULL), "pthread join");
    need(nsino("/proc/thread-self/ns/mnt") == leader_ns, "leader namespace retained");
    need(nsino("/proc/thread-self/ns/net") == leader_net, "leader network retained");
    leader_membership();
    if_freenameindex(leader_interfaces);
    printf("PASS %s: leader interface membership and indices unchanged\n", newnet ? "new-net" : "shared-net");
    char p[2048];
    snprintf(p, sizeof(p), "%s/class", target);
    struct stat s;
    need(stat(p, &s) < 0 && errno == ENOENT, "leader target unchanged");

    return 0;
}
