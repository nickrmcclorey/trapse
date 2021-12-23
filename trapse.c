#include "Zycore/Status.h"
#include "Zydis/DecoderTypes.h"
#include "Zydis/Formatter.h"
#include <Zydis/SharedTypes.h>
#include <Zydis/Zydis.h>

#ifdef MACOSX86
#include <sys/errno.h>
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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <trapse/global.h>
#include <trapse/os.h>
#include <trapse/zydis.h>

extern int errno;
extern char **environ;

typedef struct {
  char *executable_name;
  bool debug;
} Configuration;

_Bool parse_configuration(int argc, char *argv[], Configuration *config) {
  if (argc != 2) {
    config->executable_name = NULL;
    return false;
  }
  config->executable_name = argv[1];

  config->debug = false;

  return true;
}

void usage(char *invocation) { printf("Usage: %s <executable>\n", invocation); }

void print_instruction_bytes(uint8_t *instruction_bytes) {
  for (int i = 0; i < LARGEST_X86_64_INSTR; i++) {
    printf("%hhx", instruction_bytes[i]);
  }
}

// Plug and play disassemblers as long as they can adhere to this interface!
typedef struct {
  bool (*initializer)(void *);
  char *(*disassemble)(uint8_t *, uint64_t, void *);
  void *cookie;

} DisassemblerConfiguration;

// Functions for using the Zydis disassembler.

int main(int argc, char *argv[]) {
  Configuration config = {};
  pid_t trapsee_pid = 0;
  uint8_t current_instruction[LARGEST_X86_64_INSTR_PADDED] = {};
#ifdef LINUX
  struct user_regs_struct regs;
#elif MACOSX86
  typedef struct {
  } regs;
#endif
  uint64_t rip;

  int trapsee_status = 0;

  ZydisDecoder insn_decoder;
  ZydisFormatter insn_formatter;

  ZydisCookie z_cookie = {.decoder = &insn_decoder,
                          .formatter = &insn_formatter};
  DisassemblerConfiguration disassembler_configuration = {
      .initializer = zydis_initialize_disassembler,
      .disassemble = zydis_get_instruction_disassembly,
      .cookie = &z_cookie};

  disassembler_configuration.initializer(disassembler_configuration.cookie);

  if (!parse_configuration(argc, argv, &config)) {
    usage(argv[0]);
    return 1;
  }

  if (!spawn(&trapsee_pid, config.executable_name, config.debug)) {
    printf("Failed to spawn the trapsee.\n");
    return 1;
  }

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

  if (config.debug) {
    printf("Tracing child with pid %d\n", trapsee_pid);
  }

  // TODO (hawkinsw): Get the base address of the executable -- it might be
  // ASLR'd. For now we will use personality(3) above to disable ASLR.

  for (;;) {
    // Now, we loop!
#ifdef LINUX
    ptrace(PTRACE_SINGLESTEP, trapsee_pid, 0, 0);
#elif MACOSX86
    ptrace(PT_STEP, trapsee_pid, (caddr_t)1, 0);
#else
    printf("Unrecognized platform!\n");
#endif

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

    bool get_rip_success = true;
#ifdef LINUX
    // Let's try to get the rip!
    if (ptrace(PTRACE_GETREGS, trapsee_pid, NULL, &regs)) {
      get_rip_success = false;
    }
    rip = regs.rip;
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
#else
    rip = 0;
#endif

    if (!get_rip_success) {
      exit_because(errno, trapsee_pid);
    }

    if (config.debug) {
      printf("rip: 0x%llx\n", rip);
    }

    if (!get_instruction_bytes(trapsee_pid, rip, current_instruction)) {
      exit_because(errno, trapsee_pid);
    }

    if (config.debug) {
      print_instruction_bytes(current_instruction);
      printf("\n");
    }

    char *disassembled = disassembler_configuration.disassemble(
        current_instruction, rip, disassembler_configuration.cookie);
    printf("0x%llx: %s\n", rip, disassembled);
    free(disassembled);
  }

  if (config.debug) {
    printf("Trapsee exited ...\n");
  }
  return 0;
}
