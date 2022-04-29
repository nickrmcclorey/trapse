#include "Zycore/Status.h"
#include "Zydis/DecoderTypes.h"
#include "Zydis/Formatter.h"
#include <Zydis/SharedTypes.h>
#include <Zydis/Zydis.h>

#if defined MACOSX86
#include <sys/errno.h>
#elif defined WINX86
#include <Windows.h>
#include <errno.h>
#else
#include <errno.h>
#include <error.h>
#include <linux/unistd.h>
#include <sys/personality.h>
#endif

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined LINUX || defined MACOSX86
#include <sys/ptrace.h>
#endif
#include <sys/types.h>
#if defined LINUX || defined MACOSX86
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined LINUX && defined ARM
#include <elf.h>
#include <sys/uio.h>
#include <trapse/capstone_arm.h>
#endif

#include <trapse/global.h>
#include <trapse/os.h>
#include <trapse/zydis.h>

extern int errno;
extern char **environ;

// Functions for using the Zydis disassembler.

int main(int argc, char *argv[]) {
  Configuration config = {.debug = false, .executable_name = NULL};
#if defined LINUX || defined MACOSX86
  pid_t trapsee_pid = 0;
#else
  DWORD trapsee_pid = 0;
#endif
  FILE * fp;
  fp = fopen ("Exported.txt", "w");

  uint8_t current_instruction[LARGEST_X86_64_INSTR_PADDED] = {
      0,
  };
#ifdef LINUX
  struct user_regs_struct regs;
#elif MACOSX86
  typedef struct {
  } regs;
#endif
  uint64_t rip;

  int trapsee_status = 0;

#ifdef ARM
  CapstoneArmCookie csa_cookie = {};
  DisassemblerConfiguration disassembler_configuration = {
      .initializer = capstone_arm_initialize_disassembler,
      .disassemble = capstone_arm_get_instruction_disassembly,
      .cookie = &csa_cookie};
#else
  ZydisDecoder insn_decoder;
  ZydisFormatter insn_formatter;

  ZydisCookie z_cookie = {.decoder = &insn_decoder,
                          .formatter = &insn_formatter};
  DisassemblerConfiguration disassembler_configuration = {
      .initializer = zydis_initialize_disassembler,
      .disassemble = zydis_get_instruction_disassembly,
      .cookie = &z_cookie};
#endif

  disassembler_configuration.initializer(disassembler_configuration.cookie);

  if (!parse_configuration(argc, argv, &config)) {
    usage(argv[0]);
    return 1;
  }

#if defined MACOSX || defined LINUX
  if (!spawn(&trapsee_pid, config.executable_name, config.debug)) {
#elif defined WINX86
  if (!spawn(&trapsee_pid, config.executable_name, config.debug)) {
#else
  if (false) {
#endif
    exit_because(errno, 0);
  }

#if defined MACOSX || defined LINUX
  // Do a post-execve waitpid just to make sure that everything
  // went according to plan ...

  if (config.debug) {
    printf("About to waitpid for the trapsee.\n");
  }

  waitpid(trapsee_pid, &trapsee_status, 0);
  if (WIFEXITED(trapsee_status)) {
    printf("The trapsee has died before it could be trapsed.\n");
    return 1;
  }
#endif

  if (config.debug) {
    printf("Tracing child with pid %d\n", trapsee_pid);
  }

  // TODO (hawkinsw): Get the base address of the executable -- it might be
  // ASLR'd. For now we will use personality(3) above to disable ASLR.

  for (;;) {
    // Now, we loop!
#if defined LINUX
    ptrace(PTRACE_SINGLESTEP, trapsee_pid, 0, 0);
#elif defined MACOSX86
    ptrace(PT_STEP, trapsee_pid, (caddr_t)1, 0);
#elif defined WINX86
    // Nothing required.
#else
  printf("Unrecognized platform!\n");
#endif

#if defined MACOSX || defined LINUX
    if (config.debug) {
      printf("We are waitingpid ...\n");
    }
    waitpid(trapsee_pid, &trapsee_status, 0);

    if (WIFSTOPPED(trapsee_status)) {
      if (config.debug) {
        printf("Trapsee stopped ...\n");
      }
    }

    if (WIFEXITED(trapsee_status)) {
      if (config.debug) {
        printf("Trapsee has exited!\n");
      }
      break;
    }
#elif defined WINX86
    DEBUG_EVENT debugEvent;
    HANDLE threadHandle = NULL;
    memset(&debugEvent, 0, sizeof(LPDEBUG_EVENT));

    WaitForDebugEvent(&debugEvent, INFINITE);

    switch (debugEvent.dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT: {
      switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
      case EXCEPTION_SINGLE_STEP: {
        threadHandle =
            OpenThread(THREAD_ALL_ACCESS, TRUE, debugEvent.dwThreadId);
        if (threadHandle == NULL) {
          fprintf(stderr, "Error opening the trapsed thread.\n");
          exit_because(GetLastError(), trapsee_pid);
        }
        if (!set_singlestep(&threadHandle)) {
          fprintf(stderr, "Could not set single-stepping mode in a thread.\n");
          exit_because(GetLastError(), trapsee_pid);
        }
        break;
      }
      default:
        if (config.debug) {
          printf("Unrecognized debug event exception!\n");
        }
        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                                DBG_CONTINUE)) {
          exit_because(GetLastError(), trapsee_pid);
        }
        continue;
      }
      break;
    }
    case CREATE_PROCESS_DEBUG_EVENT: {
      if (config.debug) {
        printf("Windows process being created.\n");
      }
      if (!set_singlestep(&debugEvent.u.CreateProcessInfo.hThread)) {
        fprintf(stderr, "Could not set single-stepping mode in a thread.\n");
        exit_because(GetLastError(), trapsee_pid);
      }
      if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                              DBG_CONTINUE)) {
        exit_because(GetLastError(), trapsee_pid);
      }
      continue;
    }
    case CREATE_THREAD_DEBUG_EVENT: {
      if (config.debug) {
        printf("Thread being created!\n");
      }
      if (!set_singlestep(&debugEvent.u.CreateProcessInfo.hThread)) {
        fprintf(stderr, "Could not set single-stepping mode in a thread.\n");
        // exit_because(GetLastError(), trapsee_pid);
      }
      if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                              DBG_CONTINUE)) {
        exit_because(GetLastError(), trapsee_pid);
      }
      continue;
    }
    case EXIT_PROCESS_DEBUG_EVENT: {
      if (config.debug) {
        printf("Process exiting!\n");
      }
      // We only want the debugger to stop if the process exiting
      // is that of the immediate trapsee.
      DWORD exiting_pid = debugEvent.dwProcessId;
      if (exiting_pid == trapsee_pid) {
        printf("Trapsee finished...\n");
        exit(0);
      }
    }
    default: {
      if (config.debug) {
        printf("Unhandled debug event.\n");
      }
      if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                              DBG_CONTINUE)) {
        exit_because(GetLastError(), trapsee_pid);
      }
      continue;
    }
    }
#endif

    bool get_rip_success = true;
    // Let's try to get the rip!
#ifdef LINUX
#ifdef ARM
    get_rip_success = true;
    struct iovec result = {.iov_base = &regs, .iov_len = sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, trapsee_pid, NT_PRSTATUS, &result)) {
      get_rip_success = false;
    }
    rip = regs.pc;
#else
    if (ptrace(PTRACE_GETREGS, trapsee_pid, NULL, &regs)) {
      get_rip_success = false;
    }
    rip = regs.rip;
#endif
#elif MACOSX86
    kern_return_t success;
    mach_port_t port;
    thread_act_array_t threads;
    mach_msg_type_number_t threads_count = 1,
                           state_count = x86_THREAD_STATE64_COUNT;
    x86_thread_state64_t thread_state;

    get_rip_success =
        KERN_SUCCESS == task_for_pid(mach_task_self(), trapsee_pid, &port);
    get_rip_success =
        get_rip_success &&
        (KERN_SUCCESS == task_threads(port, &threads, &threads_count));
    get_rip_success =
        get_rip_success &&
        (KERN_SUCCESS == thread_get_state(threads[0], x86_THREAD_STATE64,
                                          (thread_state_t)&thread_state,
                                          &state_count));

    rip = thread_state.__rip;
#elif defined WINX86
    assert(threadHandle != NULL);

    if (!get_rip(&threadHandle, &rip)) {
      get_rip_success = false;
      errno = GetLastError();
    }
#else
  rip = 0;
#endif

    if (!get_rip_success) {
      exit_because(errno, trapsee_pid);
    }

    if (config.debug) {
      printf("rip: 0x%lx\n", rip);
    }

    if (!get_instruction_bytes(trapsee_pid, rip, current_instruction)) {
      exit_because(errno, trapsee_pid);
    }

    if (config.debug) {
      printf("Current instruction bytes: ");
      print_instruction_bytes(current_instruction);
      printf("\n");
    }

#if defined LINUX && !defined ARM 

  if (config.rip_entry) {
	static bool seen_entry = false;
	if (rip == config.rip_entry || seen_entry) {
	  seen_entry = true;
	  rip = rip - config.entry_offset;
	} else {
      continue;
    }
  }

  if (config.which_registers != NULL){ //&& export text is selected)  
    if(strstr(config.which_registers, "rax") != NULL){
      printf("rax:0x%llx ", regs.rax);
      fprintf(fp,"rax:0x%llx ", regs.rax);
    }
    if(strstr(config.which_registers, "rcx") != NULL){
      printf("rcx:0x%llx ", regs.rcx);
      fprintf(fp,"rcx:0x%llx ", regs.rcx);
    }
    if(strstr(config.which_registers, "rdx") != NULL){
      printf("rdx:0x%llx ", regs.rdx);
      fprintf(fp,"rdx:0x%llx ", regs.rdx);
    }
    if(strstr(config.which_registers, "rsi") != NULL){
      printf("rsi:0x%llx ", regs.rsi);
      fprintf(fp,"rsi:0x%llx ", regs.rsi);
    }
    if(strstr(config.which_registers, "rdi") != NULL){
      printf("rdi:0x%llx ", regs.rdi);
      fprintf(fp,"rdi:0x%llx ", regs.rdi);
    }
    if(strstr(config.which_registers, "rbp") != NULL){
      printf("rbp:0x%llx ", regs.rbp);
      fprintf(fp,"rbp:0x%llx ", regs.rbp);
    }
    if(strstr(config.which_registers, "rsp") != NULL){
      printf("rsp:0x%llx ", regs.rsp);
      fprintf(fp,"rsp:0x%llx ", regs.rsp);
    }
    if(strstr(config.which_registers, "r15") != NULL){
      printf("r15:0x%llx ", regs.r15);
      fprintf(fp,"r15:0x%llx ", regs.r15);
    }
    if(strstr(config.which_registers, "r14") != NULL){
      printf("r14:0x%llx ", regs.r14);
      fprintf(fp,"r14:0x%llx ", regs.r14);
    }
    if(strstr(config.which_registers, "r13") != NULL){
      printf("r13:0x%llx ", regs.r13);
      fprintf(fp,"r13:0x%llx ", regs.r13);
    }
    if(strstr(config.which_registers, "r12") != NULL){
      printf("r12:0x%llx ", regs.r12);
      fprintf(fp,"r12:0x%llx ", regs.r12);
    }
    if(strstr(config.which_registers, "r11") != NULL){
      printf("r11:0x%llx ", regs.r11);
      fprintf(fp,"r11:0x%llx ", regs.r11);
    }  
    if(strstr(config.which_registers, "rbx") != NULL){
      printf("rbx:0x%llx ", regs.rbx);
      fprintf(fp,"rbx:0x%llx ", regs.rbx);
    }  
    if(strstr(config.which_registers, "r10") != NULL){
      printf("r10:0x%llx ", regs.r10);
      fprintf(fp,"r10:0x%llx ", regs.r10);
    }
    if(strstr(config.which_registers, "r9") != NULL){
      printf("r9:0x%llx ", regs.r9);
      fprintf(fp,"r9:0x%llx ", regs.r9);
    }
    if(strstr(config.which_registers, "r8") != NULL){
      printf("r8:0x%llx ", regs.r8);
      fprintf(fp,"r8:0x%llx ", regs.r8);
    }
    if(strstr(config.which_registers, "orig_rax") != NULL){
      printf("orig_rax:0x%llx ", regs.orig_rax);
      fprintf(fp,"orig_rax:0x%llx ", regs.orig_rax);
    }
    if(strstr(config.which_registers, "rip") != NULL){
      printf("rip:0x%llx ", regs.rip);
      fprintf(fp,"rip:0x%llx ", regs.rip);
    }
    if(strstr(config.which_registers, "cs") != NULL){
      printf("cs:0x%llx ", regs.cs);
      fprintf(fp,"cs:0x%llx ", regs.cs);
    }
    if(strstr(config.which_registers, "eflags") != NULL){
      printf("eflags:0x%llx ", regs.eflags);
      fprintf(fp,"eflags:0x%llx ", regs.eflags);
    }
    if(strstr(config.which_registers, "ss") != NULL){
      printf("ss:0x%llx ", regs.ss);
      fprintf(fp,"ss:0x%llx ", regs.ss);
    }
    if(strstr(config.which_registers, "fs_base") != NULL){
      printf("fs_base:0x%llx ", regs.fs_base);
      fprintf(fp,"fs_base:0x%llx ", regs.fs_base);
    }
    if(strstr(config.which_registers, "gs_base") != NULL){
      printf("gs_base:0x%llx ", regs.gs_base);
      fprintf(fp,"gs_base:0x%llx ", regs.gs_base);
    }
    if(strstr(config.which_registers, "ds") != NULL){
      printf("ds:0x%llx ", regs.ds);
      fprintf(fp,"ds:0x%llx ", regs.ds);
    }
    if(strstr(config.which_registers, "es") != NULL){
      printf("es:0x%llx ", regs.es);
      fprintf(fp,"es:0x%llx ", regs.es);
    }
    if(strstr(config.which_registers, "fs") != NULL){
      printf("fs:0x%llx ", regs.fs);
      fprintf(fp,"fs:0x%llx ", regs.fs);
    }
    if(strstr(config.which_registers, "gs") != NULL){
      printf("gs:0x%llx ", regs.gs);
      fprintf(fp,"gs:0x%llx ", regs.gs);
    }
	fprintf(fp, "\n");
	printf("\n");
  }

#endif

    char *disassembled = disassembler_configuration.disassemble(
        current_instruction, rip, disassembler_configuration.cookie);
    printf("0x%lx: %s\n", rip, disassembled);
    fprintf(fp,"0x%lx: %s\n", rip, disassembled);

    free(disassembled);

#if defined WINX86
    if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                            DBG_CONTINUE)) {
      exit_because(GetLastError(), trapsee_pid);
    }

#endif
  }

  if (config.debug) {
    printf("Trapsee exited ...\n");
  }
  fclose(fp);
  return 0;
}
