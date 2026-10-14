#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/mount.h>
#include <linux/nsfs.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Internal synchronous helper. FDs supplied exclusively by sysbox-fs:
 * 3 outer user, 4 outer mount, 5 requester user, 6 requester mount,
 * 7 requester PID, 8 target directory, 9 outer root, 10 requester thread pidfd,
 * 11+ protected sources. Only trusted host proc metadata is opened before mapped-user entry;
 * every mount operation runs in the registered mapped user namespace. */
static void die(const char *s) { int e=errno?errno:EIO;fprintf(stderr,"proc-transfer: %s: %s\n",s,strerror(e));_exit(e<256?e:EIO); }
static void ck(int r,const char*s){if(r<0)die(s);}
static void need(int yes,const char*s){if(!yes){errno=EPERM;die(s);}}
static int same(int a,int b){struct stat x,y;ck(fstat(a,&x),"stat fd");ck(fstat(b,&y),"stat fd");return x.st_dev==y.st_dev&&x.st_ino==y.st_ino;}
static void guard(void){pid_t p=getppid();need(p>1,"live helper parent");ck(prctl(PR_SET_PDEATHSIG,SIGKILL),"parent death");need(p==getppid(),"parent alive");alarm(20);}
static void putat(int proc,pid_t child,const char*name,const char*s){char p[80];snprintf(p,sizeof(p),"%d/%s",child,name);int f=openat(proc,p,O_WRONLY|O_CLOEXEC);ck(f,p);if(write(f,s,strlen(s))!=(ssize_t)strlen(s))die("map write");close(f);}
static int waitcode(pid_t p){int s;ck(waitpid(p,&s,0),"wait");return WIFEXITED(s)?WEXITSTATUS(s):EIO;}
static void sendfd(int s,int f){char c='F',b[CMSG_SPACE(sizeof(int))]={0};struct iovec v={&c,1};struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=b,.msg_controllen=sizeof(b)};struct cmsghdr *h=CMSG_FIRSTHDR(&m);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(h),&f,sizeof(f));ck(sendmsg(s,&m,MSG_NOSIGNAL),"send tree");}
static int recvfd(int s){char c,b[CMSG_SPACE(sizeof(int))]={0};struct iovec v={&c,1};struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=b,.msg_controllen=sizeof(b)};if(recvmsg(s,&m,MSG_CMSG_CLOEXEC)!=1)die("receive tree");struct cmsghdr*h=CMSG_FIRSTHDR(&m);need(h&&h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SCM_RIGHTS&&h->cmsg_len==CMSG_LEN(sizeof(int))&&!(m.msg_flags&MSG_CTRUNC),"tree fd protocol");int f;memcpy(&f,CMSG_DATA(h),sizeof(f));return f;}
/* FD 10 is PIDFD_THREAD: nonleader exit is observable without group exit.
 * A prematurely exited/replaced leader may remain unreadable while its group
 * survives. Notification invalidation is a separate condition, checked by the daemon. */
static void alive(void){
 struct pollfd p={10,POLLIN,0};int r;
 do{r=poll(&p,1,0);}while(r<0&&errno==EINTR);
 ck(r,"pidfd poll");
 if(r){errno=(p.revents&POLLNVAL)?EBADF:ESRCH;die("requester alive");}
}
static unsigned long number(const char*s){char *end;errno=0;unsigned long n=strtoul(s,&end,10);need(!errno&&*s&&!*end,"numeric argument");return n;}
int main(int argc,char**argv){
 guard();need(geteuid()==0,"root launcher");need(argc>=4&&argc<=132,"argument count");
 unsigned long uid=number(argv[1]),gid=number(argv[2]),flags=number(argv[3]);int count=argc-4;
 need(!(flags&~(MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME|MS_STRICTATIME|MS_SILENT|MS_LAZYTIME)),"supported proc flags");
 need(ioctl(3,NS_GET_NSTYPE)==CLONE_NEWUSER&&ioctl(4,NS_GET_NSTYPE)==CLONE_NEWNS&&ioctl(5,NS_GET_NSTYPE)==CLONE_NEWUSER&&ioctl(6,NS_GET_NSTYPE)==CLONE_NEWNS&&ioctl(7,NS_GET_NSTYPE)==CLONE_NEWPID,"namespace types");
 int parent=ioctl(5,NS_GET_PARENT);ck(parent,"requester user parent");need(same(parent,3),"direct child user namespace");close(parent);
 int owner=ioctl(6,NS_GET_USERNS);ck(owner,"mount owner");need(same(owner,5),"requester mount owner");close(owner);
 owner=ioctl(7,NS_GET_USERNS);ck(owner,"pid owner");need(same(owner,5),"requester pid owner");close(owner);
 int launcher=open("/proc/self/ns/user",O_RDONLY|O_CLOEXEC);ck(launcher,"launcher user namespace");
 parent=ioctl(3,NS_GET_PARENT);ck(parent,"outer user parent");need(same(launcher,parent),"trusted parent-user launcher");close(launcher);close(parent);
 struct stat target;ck(fstat(8,&target),"target stat");need(S_ISDIR(target.st_mode),"directory target");alive();
 /* Keep this worker outside all container PID namespaces. The trusted proc
  * metadata FD is private and closed before entering the requester mount ns.
  * No host mount or initial-user mount privilege is used. */
 int hostproc=open("/proc",O_PATH|O_DIRECTORY|O_CLOEXEC);ck(hostproc,"trusted proc metadata");
 ck(prctl(PR_SET_DUMPABLE,0),"launcher nondumpable");
 /* Drop inherited host groups and initial-user mount privileges. */
 ck(setgroups(0,NULL),"clear launcher supplementary groups");
 ck(setns(3,CLONE_NEWUSER),"enter mapped user");ck(setgid(0),"mapped gid");ck(setuid(0),"mapped uid");
 /* A UID/GID transition clears PDEATHSIG. Restore it after mapped-root entry. */
 guard();
 ck(prctl(PR_SET_DUMPABLE,0),"mapped worker nondumpable");
 FILE *maps=fopen("/proc/self/uid_map","re");if(!maps)die("mapped uid map");unsigned a,b,c;need(fscanf(maps,"%u %u %u",&a,&b,&c)==3&&a==0&&b!=0&&c>uid,"mapped-root identity");fclose(maps);
 ck(setns(4,CLONE_NEWNS),"enter outer mount");ck(fchdir(9),"outer root fd");ck(chroot("."),"outer root");ck(chdir("/"),"root cwd");
 struct stat sources[128];unsigned long sourceflags[128];int trees[128];
 for(int i=0;i<count;i++){
  const char *p=argv[4+i];need(*p&&*p!='/'&&!strstr(p,"..")&&!strchr(p,'\\'),"relative protection path");
  ck(fstat(11+i,&sources[i]),"protected source stat");struct statvfs v;ck(fstatvfs(11+i,&v),"protected source flags");sourceflags[i]=v.f_flag;
  trees[i]=syscall(SYS_open_tree,11+i,"",AT_EMPTY_PATH|OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE);ck(trees[i],"clone protected source");
 }
 ck(unshare(CLONE_NEWNS),"private staging namespace");ck(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL),"private propagation");
 /* Stage paths live in a private tmpfs, inaccessible through shared /tmp.
  * Pin its mountpoint and use the detached tmpfs FD for the working directory, so a
  * concurrent rename in the container cannot redirect later path lookups. */
 int tmp=open("/tmp",O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);ck(tmp,"pin staging mountpoint");
 int tmpctx=syscall(SYS_fsopen,"tmpfs",FSOPEN_CLOEXEC);ck(tmpctx,"private tmpfs context");
 ck(syscall(SYS_fsconfig,tmpctx,FSCONFIG_SET_STRING,"mode","0700",0),"private tmpfs mode");
 ck(syscall(SYS_fsconfig,tmpctx,FSCONFIG_SET_STRING,"size","1m",0),"bounded private tmpfs");
 ck(syscall(SYS_fsconfig,tmpctx,FSCONFIG_CMD_CREATE,NULL,NULL,0),"create private tmpfs");
 int scratch=syscall(SYS_fsmount,tmpctx,FSMOUNT_CLOEXEC,MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC);ck(scratch,"private tmpfs mount");close(tmpctx);
 ck(syscall(SYS_move_mount,scratch,"",tmp,"",MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH),"attach private staging tmpfs");close(tmp);
 ck(fchdir(scratch),"private staging cwd");close(scratch);
 guard();char work[]="stage";ck(mkdir(work,0700),"stage directory");
 /* procfs pidns= FD creates the sandbox's own proc tree without placing a
  * helper in its PID namespace. Unsupported kernels fail closed here. */
 int fs=syscall(SYS_fsopen,"proc",FSOPEN_CLOEXEC);ck(fs,"open proc context");
 ck(syscall(SYS_fsconfig,fs,FSCONFIG_SET_FD,"pidns",NULL,7),"select proc pid namespace fd");
 if(flags&MS_LAZYTIME)ck(syscall(SYS_fsconfig,fs,FSCONFIG_SET_FLAG,"lazytime",NULL,0),"proc lazytime");
 ck(syscall(SYS_fsconfig,fs,FSCONFIG_CMD_CREATE,NULL,NULL,0),"create sandbox proc context");
 unsigned attrs=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC;
 if(flags&MS_RDONLY)attrs|=MOUNT_ATTR_RDONLY;
 if(flags&MS_STRICTATIME)attrs|=MOUNT_ATTR_STRICTATIME;
 int fresh=syscall(SYS_fsmount,fs,FSMOUNT_CLOEXEC,attrs);ck(fresh,"mount sandbox proc context");close(fs);
 ck(syscall(SYS_move_mount,fresh,"",AT_FDCWD,work,MOVE_MOUNT_F_EMPTY_PATH),"stage sandbox proc tree");close(fresh);
 for(int i=0;i<count;i++){
  char p[1024];need(snprintf(p,sizeof(p),"%s/%s",work,argv[4+i])<(int)sizeof(p),"protection path length");
  ck(syscall(SYS_move_mount,trees[i],"",AT_FDCWD,p,MOVE_MOUNT_F_EMPTY_PATH),"attach protected source");close(trees[i]);
  struct stat st;struct statvfs v;ck(stat(p,&st),"protected target stat");ck(statvfs(p,&v),"protected target flags");
  need(st.st_dev==sources[i].st_dev&&st.st_ino==sources[i].st_ino&&(!(sourceflags[i]&ST_RDONLY)||(v.f_flag&ST_RDONLY)),"protected source identity and readonly");
 }
 /* proc root has the kernel's initial-root inode owner. It is deliberately
  * not changed with initial-user capabilities. In a one-UID sandbox it is
  * shown as the overflow UID, as with native unprivileged procfs mounts.
  * PID entries retain the sandbox processes' mapped ownership. */
 (void)gid;
 if(flags&MS_RDONLY){struct mount_attr attr={.attr_set=MOUNT_ATTR_RDONLY};ck(syscall(SYS_mount_setattr,AT_FDCWD,work,AT_RECURSIVE,&attr,sizeof(attr)),"recursive readonly proc");}
 char first[1024];snprintf(first,sizeof(first),"%s/1/ns/pid",work);int p=open(first,O_RDONLY|O_CLOEXEC);ck(p,"proc pid identity");need(same(p,7),"proc is sandbox pid namespace");close(p);
 /* A sacrificial child user namespace locks every protected submount. Its
  * detached tree is passed back to the mapped outer worker, never the sandbox. */
 int pair[2];ck(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair),"locker channel");pid_t locker=fork();ck(locker,"fork locker");
 if(!locker){guard();close(pair[0]);ck(unshare(CLONE_NEWUSER),"locker user");ck(prctl(PR_SET_DUMPABLE,1),"locker proc mapping ownership");char ready='R';ck(write(pair[1],&ready,1),"locker mapping ready");need(read(pair[1],&ready,1)==1&&ready=='A',"locker mapping acknowledgement");close(hostproc);ck(prctl(PR_SET_DUMPABLE,0),"locker nondumpable");ck(unshare(CLONE_NEWNS),"lock staged mount tree");int t=syscall(SYS_open_tree,AT_FDCWD,work,OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE);ck(t,"clone locked proc tree");sendfd(pair[1],t);close(t);_exit(0);}
 close(pair[1]);char ready;need(read(pair[0],&ready,1)==1&&ready=='R',"locker ready protocol");
 putat(hostproc,locker,"uid_map","0 0 1\n");putat(hostproc,locker,"setgroups","deny");putat(hostproc,locker,"gid_map","0 0 1\n");
 ready='A';ck(write(pair[0],&ready,1),"locker mapped acknowledgement");close(hostproc);
 int tree=recvfd(pair[0]);close(pair[0]);int code=waitcode(locker);if(code)_exit(code);
 ck(umount2(work,MNT_DETACH),"discard private stage");ck(rmdir(work),"remove stage directory");
 ck(setns(6,CLONE_NEWNS),"enter sandbox mount");alive();
 /* Last operation is the atomic commit; every earlier failure leaves target
  * unchanged and destroys the private/detached trees on process exit. */
 ck(syscall(SYS_move_mount,tree,"",8,"",MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH),"commit locked proc tree");close(tree);return 0;
}
