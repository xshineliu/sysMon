/*
  ptr_inspect.c

  Demonstration code; shows how to trace the system calls in a child
  process with ptrace.  Only works on 64-bit x86 Linux for now, I'm
  afraid.  (Even worse, it's only tested on Linux 2.6....) 
 
  The callname() function looks clunky and machine-generated because it
  *is* clunky and machine-generated.

  I got inspiration and a starting point from this old LJ article:
    http://www.linuxjournal.com/article/6100 

  I release this code to the public domain.  Share and enjoy.

  Will Benton
  Madison, 2008
*/

/* 
  other refs
  http://www.secretmango.com/jimb/Whitepapers/ptrace/ptrace.html
  https://stackoverflow.com/questions/16120871/why-sigint-is-send-to-a-child-processand-does-nothing
*/

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <syscall.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

char buf[32];
unsigned long long seqNO = 0;
const char* callname(long call);
int sigval = 0;


/*
  gcc -D THREADINFO_AS_LIB  -o threadinfo.o -c threadinfo.c
*/
extern int dump_info_pid_only(int pid);


#if __WORDSIZE == 64
#define REG(reg) reg.orig_rax
#else
#define REG(reg) reg.orig_eax
#endif

int main(int argc, char* argv[]) {   
  pid_t child;
  int status;
  int ret;
  char path[128];

  struct user_regs_struct regs; 

  if (argc == 1) {
    fprintf(stderr, "Usage: %s PID\n", argv[0]);
    exit(0);
  }

  child = atoi(argv[1]);

  //ptrace(PTRACE_SEIZE, child, NULL, NULL);
  ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
  //ret = ptrace(PTRACE_ATTACH, child, NULL, &sigval);
  if (ret == -1) {
    fprintf(stderr, "Attache to PID %d Failed: errno %d\n", child, errno);
    exit(errno);
  } else {
    fprintf(stderr, "Attached to PID %d Successfully\n", child);
  }
  
  sprintf(path, "/tmp/exit_log_%d.log", child);
  freopen(path, "w", stdout);

  //ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  while(1) {
    ret = waitpid(child, &status, 0);
    if(ret == -1) {
      fprintf(stderr, "waitpid PID %d Failed: errno %d\n", child, errno);
      exit(errno);
    }
    if(ret == 0) {
      fprintf(stderr, "PID %d Exited with waitpid returned with 0.\n", child);
      break;
    }
    /* ret the pid */
    if(WIFEXITED(status)) {
      fprintf(stderr, "PID %d Exited with code %d.\n", child, WEXITSTATUS(status));
      break;
    }
    /* ret the pid */
    if(WIFSIGNALED(status)) {
      fprintf(stderr, "PID %d Exited with signal %d.\n", child, WTERMSIG(status));
      break;
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    if(REG(regs) == SYS_exit_group) {
      fprintf(stderr, " %lld - system call %d from pid %d\n", seqNO++, REG(regs), child);
      dump_info_pid_only(child);
    }
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    //ptrace(PTRACE_SYSCALL, child, NULL, &sigval);
  }

  return 0;
}
