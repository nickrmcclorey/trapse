#include "Zycore/Status.h"
#include "Zydis/DecoderTypes.h"
#include "Zydis/Formatter.h"
#include <Zydis/SharedTypes.h>
#include <Zydis/Zydis.h>
#include <errno.h>
#include <error.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>

#include <trapse/os.h>
#include <trapse/global.h>
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
  struct user_regs_struct regs;
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

  if (!spawn(&trapsee_pid, config.executable_name)) {
    return 1;
  }

  // Do a post-execve waitpid just to make sure that everything
  // went according to plan ...

  waitpid(trapsee_pid, &trapsee_status, 0);
  if (WIFEXITED(trapsee_status)) {
    printf("The trapsee has died before it could be trapsed.\n");
    return 1;
  }

  // TODO (hawkinsw): Get the base address of the executable -- it might be
  // ASLR'd. For now we will use personality(3) above to disable ASLR.

  for (;;) {
    // Now, we loop!
    ptrace(PTRACE_SINGLESTEP, trapsee_pid, 0, 0);

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

    // Let's try to get the rip!
    if (ptrace(PTRACE_GETREGS, trapsee_pid, NULL, &regs)) {
      fprintf(stderr, "Failed to get the registers: %s\n", strerror(errno));
      if (kill(trapsee_pid, SIGKILL)) {
        fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(errno));
      }
      exit(1);
    }

    if (config.debug) {
      printf("rip: 0x%llx\n", regs.rip);
    }

    if (!get_instruction_bytes(trapsee_pid, regs.rip, current_instruction)) {
      fprintf(stderr, "Could not get instruction's bytes from trapsee: %s\n",
              strerror(errno));
      if (kill(trapsee_pid, SIGKILL)) {
        fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(errno));
      }
      exit(1);
    }

    if (config.debug) {
      print_instruction_bytes(current_instruction);
      printf("\n");
    }

    char *disassembled = disassembler_configuration.disassemble(current_instruction, regs.rip, disassembler_configuration.cookie);
    printf("%llx: %s\n", regs.rip, disassembled);
    free(disassembled);
  }

  printf("Trapsee exited ...\n");
  return 0;
}