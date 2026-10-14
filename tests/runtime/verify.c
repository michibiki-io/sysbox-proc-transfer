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
static const char *names[]={"uptime","swaps","sys","bus","fs","irq","sysrq-trigger","asound","interrupts","keys","timer_list"};
static void fail(const char*s){perror(s);exit(1);}
static void need(int r,const char*s){if(!r){fprintf(stderr,"FAIL %s\n",s);exit(1);}}
static void linkstr(const char *p,char*b){ssize_t n=readlink(p,b,127);if(n<0)fail(p);b[n]=0;}
int main(int argc,char**argv){
 need(argc>=3,"arguments");
 if(!strcmp(argv[1],"readonly")){
  if(mount("proc",argv[2],"proc",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))fail("readonly proc mount");
  struct statvfs v;if(statvfs(argv[2],&v))fail("readonly root flags");need(v.f_flag&ST_RDONLY,"proc root readonly");
  for(size_t i=0;i<sizeof(names)/sizeof(*names);i++){char p[1024];snprintf(p,sizeof(p),"%s/%s",argv[2],names[i]);if(statvfs(p,&v))fail(p);need(v.f_flag&ST_RDONLY,"every protected entry readonly");}
  puts("PASS recursive readonly proc mount");return 0;
 }
 if(!strcmp(argv[1],"capture")){
  FILE*f=fopen(argv[2],"we");if(!f)fail("manifest");
  for(size_t i=0;i<sizeof(names)/sizeof(*names);i++){
   char p[256];snprintf(p,sizeof(p),"/proc/%s",names[i]);struct stat s;struct statvfs v;
   if(stat(p,&s)){need(errno==ENOENT,"source protection stat");continue;}
   if(statvfs(p,&v))fail("source flags");
   fprintf(f,"%s %lu %lu %lu\n",names[i],(unsigned long)s.st_dev,(unsigned long)s.st_ino,v.f_flag);
  }fclose(f);return 0;
 }
 need(!strcmp(argv[1],"sandbox")&&argc==4,"sandbox arguments");
 need(argv[3][0]!=0,"host pid namespace supplied");
 char pidns[128],one[128],user[128];linkstr("/proc/self/ns/pid",pidns);linkstr("/proc/1/ns/pid",one);linkstr("/proc/self/ns/user",user);
 need(!strcmp(pidns,one),"proc namespace matches sandbox");need(strcmp(pidns,argv[3]),"host pid namespace hidden");
 printf("uid=%d pid=%d pidns=%s userns=%s host_pidns=%s\n",getuid(),getpid(),pidns,user,argv[3]);
 FILE*f=fopen("/proc/self/status","re");if(!f)fail("status");char line[512];int seccomp=-1;
 unsigned long long caps=0;
 while(fgets(line,sizeof(line),f)){if(!strncmp(line,"NSpid:",6)||!strncmp(line,"Seccomp",7)||!strncmp(line,"CapEff:",7))fputs(line,stdout);sscanf(line,"Seccomp: %d",&seccomp);sscanf(line,"CapEff: %llx",&caps);}fclose(f);need(seccomp==2,"seccomp filtering retained");need(caps&(1ULL<<21),"CAP_SYS_ADMIN present for negative tests");
 f=fopen(argv[2],"re");if(!f)fail("manifest");char name[128];unsigned long dev,ino,flags;int checked=0;
 while(fscanf(f,"%127s %lu %lu %lu",name,&dev,&ino,&flags)==4){
  char p[256];snprintf(p,sizeof(p),"/proc/%s",name);struct stat s;struct statvfs v;
  if(stat(p,&s)||statvfs(p,&v))fail(p);
  need((unsigned long)s.st_dev==dev&&(unsigned long)s.st_ino==ino,"protection inode unchanged");need(!(flags&ST_RDONLY)||(v.f_flag&ST_RDONLY),"readonly retained");
  errno=0;int r=umount2(p,MNT_DETACH),e=errno;printf("protection %s inode=%lu ro=%d detach=%d errno=%d\n",name,ino,!!(v.f_flag&ST_RDONLY),r,e);need(r<0,"cannot detach protection");
  if(flags&ST_RDONLY){errno=0;r=mount(NULL,p,NULL,MS_REMOUNT|MS_BIND,NULL);printf("readonly clear %s result=%d errno=%d\n",name,r,errno);need(r<0,"cannot clear readonly");}
  checked++;
 }fclose(f);need(checked>=3,"protected entries checked");
 const char *masked[]={"keys","interrupts","timer_list"};for(int i=0;i<3;i++){char p[128],byte;snprintf(p,sizeof(p),"/proc/%s",masked[i]);int fd=open(p,O_RDONLY);if(fd<0)fail(p);need(read(fd,&byte,1)==0,"masked file empty");close(fd);}
 struct stat st;if(stat("/proc",&st))fail("proc root stat");printf("proc root owner=%u:%u\n",st.st_uid,st.st_gid);
 puts("PASS sandbox PID, user, seccomp, protection identity, masks, detach and readonly checks");return 0;
}
