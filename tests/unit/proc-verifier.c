/* Unprivileged syscall simulation of the actual runtime entry points.
 * No test switches are compiled into the shipped verifier. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
static int stub_stat(const char *,struct stat *);
static int stub_statvfs(const char *,struct statvfs *);
static int stub_mount(const char *,const char *,const char *,unsigned long,const void *);
static int stub_umount2(const char *,int);
static ssize_t stub_readlink(const char *,char *,size_t);
static FILE *stub_fopen(const char *,const char *);
static int stub_open(const char *,int,...);
static ssize_t stub_read(int,void *,size_t);
static int stub_close(int);
#define stat(...) stub_stat(__VA_ARGS__)
#define statvfs(...) stub_statvfs(__VA_ARGS__)
#define mount stub_mount
#define umount2 stub_umount2
#define readlink stub_readlink
#define fopen stub_fopen
#define open stub_open
#define read stub_read
#define close stub_close
#define main verifier_main
#include "../runtime/verify.c"
#undef main
#undef stat
#undef statvfs
#undef mount
#undef umount2
#undef readlink
#undef fopen
#undef open
#undef read
#undef close
static int matches(const char *op,const char *path){
 const char *fault=getenv("FAULT"),*target=getenv("TARGET");
 return fault&&target&&!strcmp(fault,op)&&!strcmp(target,path);
}
static int inspection_error(const char *op,const char *path){
 fprintf(stderr,"CALL %s %s\n",op,path);
 if(matches(op,path)){errno=atoi(getenv("ERROR"));return -1;}
 return 0;
}
static int stub_stat(const char *p,struct stat *s){
 if(inspection_error("stat",p))return -1;
 if(getenv("ABSENT")&&strstr(p,"/asound")){errno=ENOENT;return -1;}
 memset(s,0,sizeof(*s));s->st_dev=10;s->st_ino=20;
 if(matches("device",p))s->st_dev++;
 if(matches("inode",p))s->st_ino++;
 return 0;
}
static int stub_statvfs(const char *p,struct statvfs *v){
 if(inspection_error("statvfs",p))return -1;
 memset(v,0,sizeof(*v));v->f_flag=matches("writable",p)?0:ST_RDONLY;return 0;
}
static int stub_mount(const char *src,const char *p,const char *type,unsigned long flags,const void *data){
 (void)src;(void)type;(void)data;
 fprintf(stderr,"CALL %s %s\n",flags&MS_REMOUNT?"remount":"mount",p);
 if(flags&MS_REMOUNT){if(matches("remount",p))return 0;errno=EPERM;return -1;}
 if(matches("mount",p)){errno=EIO;return -1;}
 return 0;
}
static int stub_umount2(const char *p,int flags){
 need(flags==MNT_DETACH,"detach flags");fprintf(stderr,"CALL detach %s\n",p);
 if(matches("detach",p))return 0;
 errno=EPERM;return -1;
}
static ssize_t stub_readlink(const char *p,char *b,size_t n){
 fprintf(stderr,"CALL readlink %s\n",p);
 const char *value=strstr(p,"user")?"user:[2]":"pid:[2]";
 size_t len=strlen(value);need(len<n,"stub link buffer");memcpy(b,value,len);return (ssize_t)len;
}
static FILE *stub_fopen(const char *p,const char *mode){
 if(strcmp(p,"/proc/self/status"))return fopen(p,mode);
 fprintf(stderr,"CALL status %s\n",p);
 FILE *f=tmpfile();if(!f)fail("stub status");
 fputs("Seccomp: 2\nCapEff: 00200000\n",f);rewind(f);return f;
}
static int stub_open(const char *p,int flags,...){
 need(flags==O_RDONLY,"mask open flags");fprintf(stderr,"CALL mask %s\n",p);return 100;
}
static ssize_t stub_read(int fd,void *b,size_t n){
 (void)b;need(fd==100&&n==1,"mask read");return getenv("MASK_DATA")?1:0;
}
static int stub_close(int fd){need(fd==100,"mask close");return 0;}
int main(int argc,char **argv){return verifier_main(argc,argv);}
