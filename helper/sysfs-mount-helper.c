#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <linux/openat2.h>
#include <linux/capability.h>
#include <stdint.h>
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
 * 7 requester Network, 8 target directory, 9 outer root, 10 requester thread pidfd,
 * 11+ protected sources. Only trusted host proc metadata is opened before mapped-user entry;
 * every mount operation runs in the registered mapped user namespace. */
static void die(const char *s) { int e=errno?errno:EIO;fprintf(stderr,"sysfs-transfer: %s: %s\n",s,strerror(e));_exit(e<256?e:EIO); }
/* Backing-only protocol: 200/201 identify a genuinely missing resource.
 * Ordinary ENOENT/ENOTDIR from setup remain distinguishable by the daemon. */
static void resource_error(void) {
 int e=errno;fprintf(stderr,"sysfs-transfer: open network backing resource: %s\n",strerror(e));
 _exit(e==ENOENT?200:e==ENOTDIR?201:(e>0&&e<200?e:EIO));
}
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
static int relative_path(const char *p) {
 if(!*p||*p=='/')return 0;
 while(*p){const char *end=strchr(p,'/');size_t n=end?(size_t)(end-p):strlen(p);
  if(!n||(n==1&&p[0]=='.')||(n==2&&p[0]=='.'&&p[1]=='.'))return 0;
  if(!end)return 1;
  p=end+1;
 }
 return 0;
}
/* Backing mode returns only a caller-opened net resource FD through FD8.
 * argv4 is --lookup=relative-path or --open=relative-path. No raw tree FD
 * or write operation is exposed to the daemon or caller. */
int main(int argc,char**argv){
 guard();need(geteuid()==0,"root launcher");need(argc>=4&&argc<=133,"argument count");
 unsigned long uid=number(argv[1]),gid=number(argv[2]),flags=number(argv[3]);int backing=argc>4&&!strncmp(argv[4],"--",2), start=backing?5:4, count=argc-start;
 need(count<=128,"bounded protection count");need(uid<UINT32_MAX&&gid<UINT32_MAX,"mapped IDs");
 const char *resource=NULL;int lookup=0;
 if(backing){
  lookup=!strncmp(argv[4],"--lookup=",9);
  need(lookup||!strncmp(argv[4],"--open=",7),"backing operation");
  resource=argv[4]+(lookup?9:7);
  need(relative_path(resource),"relative backing resource");
  need(!strcmp(resource,"devices/virtual/net")||!strncmp(resource,"devices/virtual/net/",20),"network backing scope");
 }
 need(!(flags&MS_RELATIME)||!(flags&MS_STRICTATIME),"exclusive atime flags");
 need(!(flags&~(MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME|MS_STRICTATIME|MS_SILENT|MS_LAZYTIME)),"supported sysfs flags");
 need(ioctl(3,NS_GET_NSTYPE)==CLONE_NEWUSER&&ioctl(4,NS_GET_NSTYPE)==CLONE_NEWNS&&ioctl(5,NS_GET_NSTYPE)==CLONE_NEWUSER&&ioctl(6,NS_GET_NSTYPE)==CLONE_NEWNS&&ioctl(7,NS_GET_NSTYPE)==CLONE_NEWNET,"namespace types");
 int parent;
 if(!(backing&&same(5,3))){parent=ioctl(5,NS_GET_PARENT);ck(parent,"requester user parent");need(same(parent,3),"direct child user namespace");close(parent);}
 int owner=ioctl(6,NS_GET_USERNS);ck(owner,"mount owner");need(same(owner,5),"requester mount owner");close(owner);
 owner=ioctl(7,NS_GET_USERNS);ck(owner,"network owner");
 int net_ok=same(owner,5)||same(owner,3);
 /* Registered outer FUSE callers can have joined a direct child's Network.
  * This also covers mapped construction workers resolving nested protections. */
 if(!net_ok&&backing&&same(5,3)){int net_parent=ioctl(owner,NS_GET_PARENT);ck(net_parent,"outer backing network owner parent");net_ok=same(net_parent,3);close(net_parent);}
 need(net_ok,"requester or outer network owner");close(owner);
 owner=ioctl(4,NS_GET_USERNS);ck(owner,"outer mount owner");need(same(owner,3),"registered outer mount owner");close(owner);
 int launcher=open("/proc/self/ns/user",O_RDONLY|O_CLOEXEC);ck(launcher,"launcher user namespace");
 parent=ioctl(3,NS_GET_PARENT);ck(parent,"outer user parent");need(same(launcher,parent),"trusted parent-user launcher");close(launcher);close(parent);
 if(!backing){struct stat target;ck(fstat(8,&target),"target stat");need(S_ISDIR(target.st_mode),"directory target");}alive();
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
 ck(setns(4,CLONE_NEWNS),"enter outer mount");ck(fchdir(9),"outer root fd");ck(chroot("."),"outer root");ck(chdir("/"),"root cwd");ck(setns(7,CLONE_NEWNET),"requester network");
 struct stat sources[128];unsigned long sourceflags[128];int trees[128], aliases[128]; const char *paths[128];
 for(int i=0;i<count;i++){
  const char *p=argv[start+i];aliases[i]=!strncmp(p,"@ro:",4);
  if(aliases[i]){need(backing,"readonly alias only in backing");p+=4;need(!strcmp(p,"devices/virtual/net")||!strncmp(p,"devices/virtual/net/",20),"readonly alias network scope");}
  paths[i]=p;need(relative_path(p),"relative protection path");
  ck(fstat(11+i,&sources[i]),"protected source stat");struct statvfs v;ck(fstatvfs(11+i,&v),"protected source flags");sourceflags[i]=v.f_flag;
  if(aliases[i]){struct statfs fs;ck(fstatfs(11+i,&fs),"readonly alias filesystem");need(fs.f_type==FUSE_SUPER_MAGIC&&(sourceflags[i]&ST_RDONLY),"readonly FUSE alias source");trees[i]=-1;continue;}
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
 /* The actual Network namespace has been entered with mapped outer authority.
  * No IPC, UTS, Cgroup or PID namespace entry is needed. */
 int fs=syscall(SYS_fsopen,"sysfs",FSOPEN_CLOEXEC);ck(fs,"open sysfs context");
 if(flags&MS_LAZYTIME)ck(syscall(SYS_fsconfig,fs,FSCONFIG_SET_FLAG,"lazytime",NULL,0),"sysfs lazytime");
 ck(syscall(SYS_fsconfig,fs,FSCONFIG_CMD_CREATE,NULL,NULL,0),"create sandbox sysfs context");
 unsigned attrs=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC;
 if(flags&MS_RDONLY)attrs|=MOUNT_ATTR_RDONLY;
 if(flags&MS_STRICTATIME)attrs|=MOUNT_ATTR_STRICTATIME;
 int fresh=syscall(SYS_fsmount,fs,FSMOUNT_CLOEXEC,attrs);ck(fresh,"mount sandbox sysfs context");close(fs);
 ck(syscall(SYS_move_mount,fresh,"",AT_FDCWD,work,MOVE_MOUNT_F_EMPTY_PATH),"stage sandbox sysfs tree");close(fresh);
 for(int i=0;i<count;i++){
  char p[1024];need(snprintf(p,sizeof(p),"%s/%s",work,paths[i])<(int)sizeof(p),"protection path length");
  /* A named interface protection is inapplicable when that interface is
   * absent in the pinned backing Network. Preserve genuine ENOENT without
   * suppressing other failures or skipping acquisition of trusted sources. */
  if(backing&&!strncmp(paths[i],"devices/virtual/net/",20)){struct stat present;if(stat(p,&present)<0){if(errno==ENOENT){if(trees[i]>=0)close(trees[i]);continue;}die("network protection target");}}
  /* An OCI readonly self-bind of this same FUSE passthrough cannot be
   * cloned into backing: it would recursively call the same handler. Its
   * trusted source FD remains verified; recreate its readonly/security floor
   * on the raw per-request Network path. Transfer mode retains original IDs. */
  if(aliases[i]){struct statvfs v;ck(statvfs(p,&v),"readonly alias backing flags");need((v.f_flag&(ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC))==(ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC),"readonly alias backing floor");continue;}
  ck(syscall(SYS_move_mount,trees[i],"",AT_FDCWD,p,MOVE_MOUNT_F_EMPTY_PATH),"attach protected source");close(trees[i]);
  struct stat st;struct statvfs v;ck(stat(p,&st),"protected target stat");ck(statvfs(p,&v),"protected target flags");
  need(st.st_dev==sources[i].st_dev&&st.st_ino==sources[i].st_ino&&((v.f_flag&sourceflags[i]&(ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC))==(sourceflags[i]&(ST_RDONLY|ST_NOSUID|ST_NODEV|ST_NOEXEC))),"protected source identity and readonly");
 }
 struct mount_attr attr={.attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC};
 if(flags&MS_RDONLY)attr.attr_set|=MOUNT_ATTR_RDONLY;
 ck(syscall(SYS_mount_setattr,AT_FDCWD,work,AT_RECURSIVE,&attr,sizeof(attr)),"recursive sysfs security floor");
 if(backing){
  int root=open(work,O_PATH|O_DIRECTORY|O_CLOEXEC);ck(root,"backing root");close(hostproc);
  /* Resolve with caller mapped credentials and no capabilities. The FD keeps
   * the private view alive only until the bounded synchronous FUSE operation. */
  ck(setgid((gid_t)gid),"backing caller gid");ck(setuid((uid_t)uid),"backing caller uid");guard();
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3};struct __user_cap_data_struct d[2]={{0},{0}};
  ck(syscall(SYS_capset,&h,d),"clear backing capabilities");ck(prctl(PR_SET_DUMPABLE,0),"backing nondumpable");
  struct open_how how={.flags=(lookup?O_PATH|O_NOFOLLOW:O_RDONLY)|O_CLOEXEC,.resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS};
  int f=syscall(SYS_openat2,root,resource,&how,sizeof(how));if(f<0)resource_error();close(root);alive();sendfd(8,f);close(f);return 0;
 }
 /* A sacrificial child user namespace locks every protected submount. Its
  * detached tree is passed back to the mapped outer worker, never the sandbox. */
 int pair[2];ck(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair),"locker channel");pid_t locker=fork();ck(locker,"fork locker");
 if(!locker){guard();close(pair[0]);ck(unshare(CLONE_NEWUSER),"locker user");ck(prctl(PR_SET_DUMPABLE,1),"locker proc mapping ownership");char ready='R';ck(write(pair[1],&ready,1),"locker mapping ready");need(read(pair[1],&ready,1)==1&&ready=='A',"locker mapping acknowledgement");close(hostproc);ck(prctl(PR_SET_DUMPABLE,0),"locker nondumpable");ck(unshare(CLONE_NEWNS),"lock staged mount tree");int t=syscall(SYS_open_tree,AT_FDCWD,work,OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE);ck(t,"clone locked sysfs tree");sendfd(pair[1],t);close(t);_exit(0);}
 close(pair[1]);char ready;need(read(pair[0],&ready,1)==1&&ready=='R',"locker ready protocol");
 putat(hostproc,locker,"uid_map","0 0 1\n");putat(hostproc,locker,"setgroups","deny");putat(hostproc,locker,"gid_map","0 0 1\n");
 ready='A';ck(write(pair[0],&ready,1),"locker mapped acknowledgement");close(hostproc);
 int tree=recvfd(pair[0]);close(pair[0]);int code=waitcode(locker);if(code)_exit(code);
 ck(umount2(work,MNT_DETACH),"discard private stage");ck(rmdir(work),"remove stage directory");
 ck(setns(6,CLONE_NEWNS),"enter sandbox mount");alive();
 /* Last operation is the atomic commit; every earlier failure leaves target
  * unchanged and destroys the private/detached trees on process exit. */
 ck(syscall(SYS_move_mount,tree,"",8,"",MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH),"commit locked sysfs tree");close(tree);return 0;
}
