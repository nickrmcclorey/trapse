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

extern int errno;
extern char **environ;

#define LARGEST_X86_64_INSTR 15
#define LARGEST_X86_64_INSTR_PADDED 16
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

bool spawn(pid_t *child, char *trapsee_path) {
  if (!(*child = fork())) {
    char *child_argv[] = {trapsee_path, NULL};
    /*
     * We are in the child.
     */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    // TODO (hawkinsw): Temporarily disable ASLR.
    personality(ADDR_NO_RANDOMIZE);

    execve(trapsee_path, child_argv, environ);
    /*
     * If execve returns, we know it failed.
     */
    exit(1);
  }

  if (*child == -1) {
    fprintf(stderr, "Error forking trapsee: %s\n", strerror(errno));
    return false;
  }

  return true;
}

void print_instruction_bytes(uint8_t *instruction_bytes) {
  for (int i = 0; i < LARGEST_X86_64_INSTR; i++) {
    printf("%hhx", instruction_bytes[i]);
  }
}

void initialize_disassembler(ZydisDecoder *decoder, ZydisFormatter *formatter) {
  ZydisDecoderInit(decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

void print_disassembled(uint8_t *instruction_bytes, uint64_t rip,
                        ZydisDecoder *decoder, ZydisFormatter *formatter) {
  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

  if (ZYAN_FAILED((ZydisDecoderDecodeFull(
          decoder, instruction_bytes, LARGEST_X86_64_INSTR, &instruction,
          operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
          ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))) {
    printf("---DECODE FAILURE---");
    return;
  }

  char decoded_instruction_buffer[256];
  if (ZYAN_FAILED(ZydisFormatterFormatInstruction(
          formatter, &instruction, operands, instruction.operand_count_visible,
          decoded_instruction_buffer, sizeof(decoded_instruction_buffer),
          rip))) {
    printf("---DECODE FAILURE---");
  }

  puts(decoded_instruction_buffer);
}

int main(int argc, char *argv[]) {
  Configuration config = {};
  pid_t trapsee_pid = 0;
  uint8_t current_instruction[LARGEST_X86_64_INSTR_PADDED] = {};
  struct user_regs_struct regs;
  int trapsee_status = 0;

  ZydisDecoder insn_decoder;
  ZydisFormatter insn_formatter;

  initialize_disassembler(&insn_decoder, &insn_formatter);

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

    if (config.debug)
      printf("We are waitingpid ...\n");
    waitpid(trapsee_pid, &trapsee_status, 0);

    if (WIFSTOPPED(trapsee_status)) {
      if (config.debug)
        printf("Trapsee stopped ...\n");
    }

    if (WIFEXITED(trapsee_status)) {
      if (config.debug)
        printf("Trapsee has exited!\n");
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

    // Now, let's try to get the instruction's bytes!

    // Clear errno -- because the return value of the next four calls to
    // ptrace(3) return the value fetch (and not a status value), then a changed
    // errno is the only signal we have that something went wrong.
    errno = 0;

    *((uint32_t *)(&(current_instruction[0]))) =
        ptrace(PTRACE_PEEKDATA, trapsee_pid, regs.rip, NULL); // (4 bytes)
    *((uint32_t *)(&(current_instruction[sizeof(uint32_t) * 1]))) =
        ptrace(PTRACE_PEEKDATA, trapsee_pid, regs.rip + sizeof(uint32_t) * 1,
               NULL); // (4 bytes)
    *((uint32_t *)(&(current_instruction[sizeof(uint32_t) * 2]))) =
        ptrace(PTRACE_PEEKDATA, trapsee_pid, regs.rip + sizeof(uint32_t) * 2,
               NULL); // (4 bytes)
    *((uint32_t *)(&(current_instruction[sizeof(uint32_t) * 3]))) =
        ptrace(PTRACE_PEEKDATA, trapsee_pid, regs.rip + sizeof(uint32_t) * 3,
               NULL); // (4 bytes)

    if (errno) {
      fprintf(stderr, "Could not get instruction's bytes from trapsee: %s\n",
              strerror(errno));
      if (kill(trapsee_pid, SIGKILL)) {
        fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(errno));
      }
      exit(1);
    }
    // We only want the first three of the last word.

    if (config.debug) {
      print_instruction_bytes(current_instruction);
      printf("\n");
    }

    print_disassembled(current_instruction, regs.rip, &insn_decoder,
                       &insn_formatter);
  }

  printf("Trapsee exited ...\n");
  return 0;
}