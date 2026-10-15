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
/* Kernel-config-dependent asound (CONFIG_SND_PROC_FS), sysrq-trigger
 * (CONFIG_MAGIC_SYSRQ), swaps (CONFIG_SWAP) and sys (CONFIG_PROC_SYSCTL)
 * may be absent. The other seven entries, including OCI masks interrupts,
 * keys and timer_list, are required. */
static const struct { const char *name; int optional; } catalog[]={
 {"uptime",0},{"swaps",1},{"sys",1},{"bus",0},{"fs",0},{"irq",0},
 {"sysrq-trigger",1},{"asound",1},{"interrupts",0},{"keys",0},{"timer_list",0}
};
#define COUNT (sizeof(catalog)/sizeof(*catalog))
struct entry { int present; unsigned long dev,ino,flags; };
static void fail(const char*s){perror(s);exit(1);}
static void need(int r,const char*s){if(!r){fprintf(stderr,"FAIL %s\n",s);exit(1);}}
static void linkstr(const char *p,char*b){ssize_t n=readlink(p,b,127);if(n<0)fail(p);b[n]=0;}
static unsigned long number(const char *s){
 need(*s!=0,"manifest number");
 for(const char *p=s;*p;p++)need(*p>='0'&&*p<='9',"manifest decimal");
 errno=0;char *end;unsigned long n=strtoul(s,&end,10);
 need(errno!=ERANGE&&!*end,"manifest numeric range");return n;
}
/* Exact, bounded newline-terminated rows: NAME absent or NAME present DEV INO FLAGS.
 * Parse the entire file before mount/namespace/protection operations. */
static void load(const char *path,struct entry entries[COUNT]){
 FILE *f=fopen(path,"re");if(!f)fail("manifest");
 unsigned seen[COUNT]={0};size_t rows=0,total=0;int present=0,c;
 char line[256];size_t len=0;
 while((c=fgetc(f))!=EOF){
  need(++total<=4096&&c!=0,"manifest size or NUL");
  if(c!='\n'){need(len<sizeof(line)-1,"manifest row size");line[len++]=(char)c;continue;}
  line[len]=0;len=0;need(rows++<COUNT,"manifest row count");
  char *tokens[6],*save=NULL;size_t n=0;
  for(char *t=strtok_r(line," ", &save);t;t=strtok_r(NULL," ",&save)){
   need(n<6,"manifest fields");tokens[n++]=t;
  }
  need(n==2||n==5,"manifest fields");size_t i;
  for(i=0;i<COUNT;i++)if(!strcmp(tokens[0],catalog[i].name))break;
  need(i<COUNT,"manifest known candidate");need(!seen[i]++,"manifest unique candidate");
  if(n==2){
   need(!strcmp(tokens[1],"absent")&&catalog[i].optional,"manifest optional absence");
   entries[i]=(struct entry){0};
  }else{
   need(!strcmp(tokens[1],"present"),"manifest presence");
   entries[i]=(struct entry){1,number(tokens[2]),number(tokens[3]),number(tokens[4])};present++;
  }
 }
 if(ferror(f))fail("manifest read");
 need(len==0&&rows==COUNT,"manifest complete rows");
 for(size_t i=0;i<COUNT;i++)need(seen[i]==1,"manifest complete catalog");
 need(present>=3,"protected entries baseline");if(fclose(f))fail("manifest close");
}
static void capture(const char *path){
 struct entry entries[COUNT];
 for(size_t i=0;i<COUNT;i++){
  char p[256];snprintf(p,sizeof(p),"/proc/%s",catalog[i].name);struct stat s;struct statvfs v;
  if(stat(p,&s)){
   need(errno==ENOENT&&catalog[i].optional,"source protection stat");
   entries[i]=(struct entry){0};continue;
  }
  if(statvfs(p,&v))fail("source flags");
  entries[i]=(struct entry){1,(unsigned long)s.st_dev,(unsigned long)s.st_ino,v.f_flag};
 }
 FILE *f=fopen(path,"we");if(!f)fail("manifest");
 for(size_t i=0;i<COUNT;i++){
  struct entry e=entries[i];int r;
  if(e.present)r=fprintf(f,"%s present %lu %lu %lu\n",catalog[i].name,e.dev,e.ino,e.flags);
  else r=fprintf(f,"%s absent\n",catalog[i].name);
  if(r<0)fail("manifest write");
 }
 if(fclose(f))fail("manifest close");
}
/* Check absence with stat: only ENOENT is an expected observation. */
static int observe(const char *p,const struct entry *e,struct stat *s,struct statvfs *v){
 int r=stat(p,s);
 if(!e->present){need(r<0&&errno==ENOENT,"expected optional absence");return 0;}
 if(r)fail(p);
 if(statvfs(p,v))fail(p);
 return 1;
}
int main(int argc,char**argv){
 need(argc>=3,"arguments");
 if(!strcmp(argv[1],"capture")){need(argc==3,"capture arguments");capture(argv[2]);return 0;}
 int readonly=!strcmp(argv[1],"readonly");
 need(argc==4&&(readonly||!strcmp(argv[1],"sandbox")),"consumer arguments");
 struct entry entries[COUNT];load(argv[readonly?3:2],entries);
 if(readonly){
  if(mount("proc",argv[2],"proc",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))fail("readonly proc mount");
  struct statvfs v;if(statvfs(argv[2],&v))fail("readonly root flags");need(v.f_flag&ST_RDONLY,"proc root readonly");
  int checked=0;
  for(size_t i=0;i<COUNT;i++){
   char p[1024];struct stat st;
   need(snprintf(p,sizeof(p),"%s/%s",argv[2],catalog[i].name)<(int)sizeof(p),"proc path size");
   if(!observe(p,&entries[i],&st,&v))continue;
   need(v.f_flag&ST_RDONLY,"every protected entry readonly");checked++;
  }
  need(checked>=3,"protected entries checked");
  puts("PASS recursive readonly proc mount");return 0;
 }
 need(!strcmp(argv[1],"sandbox")&&argc==4,"sandbox arguments");
 need(argv[3][0]!=0,"host pid namespace supplied");
 char pidns[128],one[128],user[128];linkstr("/proc/self/ns/pid",pidns);linkstr("/proc/1/ns/pid",one);linkstr("/proc/self/ns/user",user);
 need(!strcmp(pidns,one),"proc namespace matches sandbox");need(strcmp(pidns,argv[3]),"host pid namespace hidden");
 printf("uid=%d pid=%d pidns=%s userns=%s host_pidns=%s\n",getuid(),getpid(),pidns,user,argv[3]);
 FILE*f=fopen("/proc/self/status","re");if(!f)fail("status");char line[512];int seccomp=-1;
 unsigned long long caps=0;
 while(fgets(line,sizeof(line),f)){if(!strncmp(line,"NSpid:",6)||!strncmp(line,"Seccomp",7)||!strncmp(line,"CapEff:",7))fputs(line,stdout);sscanf(line,"Seccomp: %d",&seccomp);sscanf(line,"CapEff: %llx",&caps);}fclose(f);need(seccomp==2,"seccomp filtering retained");need(caps&(1ULL<<21),"CAP_SYS_ADMIN present for negative tests");
 int checked=0;
 for(size_t i=0;i<COUNT;i++){
  const char *name=catalog[i].name;struct entry e=entries[i];
  char p[256];snprintf(p,sizeof(p),"/proc/%s",name);struct stat s;struct statvfs v;
  if(!observe(p,&e,&s,&v))continue;
  need((unsigned long)s.st_dev==e.dev&&(unsigned long)s.st_ino==e.ino,"protection inode unchanged");need(!(e.flags&ST_RDONLY)||(v.f_flag&ST_RDONLY),"readonly retained");
  errno=0;int r=umount2(p,MNT_DETACH),error=errno;printf("protection %s inode=%lu ro=%d detach=%d errno=%d\n",name,e.ino,!!(v.f_flag&ST_RDONLY),r,error);need(r<0,"cannot detach protection");
  if(e.flags&ST_RDONLY){errno=0;r=mount(NULL,p,NULL,MS_REMOUNT|MS_BIND,NULL);printf("readonly clear %s result=%d errno=%d\n",name,r,errno);need(r<0,"cannot clear readonly");}
  checked++;
 }
 need(checked>=3,"protected entries checked");
 const char *masked[]={"keys","interrupts","timer_list"};for(int i=0;i<3;i++){char p[128],byte;snprintf(p,sizeof(p),"/proc/%s",masked[i]);int fd=open(p,O_RDONLY);if(fd<0)fail(p);need(read(fd,&byte,1)==0,"masked file empty");close(fd);}
 struct stat st;if(stat("/proc",&st))fail("proc root stat");printf("proc root owner=%u:%u\n",st.st_uid,st.st_gid);
 puts("PASS sandbox PID, user, seccomp, protection identity, masks, detach and readonly checks");return 0;
}
