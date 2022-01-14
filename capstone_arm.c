#include <stdbool.h>
#include <string.h>
#include <trapse/capstone_arm.h>
#include <trapse/global.h>

_Bool capstone_arm_initialize_disassembler(void *cookie) {
  CapstoneArmCookie *csa_cookie = (CapstoneArmCookie *)cookie;
  csa_cookie->handle = (csh *)calloc(sizeof(csh), 1);

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, csa_cookie->handle) != CS_ERR_OK) {
    return false;
  }
  return true;
}

char *capstone_arm_get_instruction_disassembly(uint8_t *instruction_bytes,
                                               uint64_t rip, void *cookie) {
  CapstoneArmCookie *csa_cookie = (CapstoneArmCookie *)cookie;
  cs_insn *insn = NULL;
  size_t instructions_in_bytes = 0;
  instructions_in_bytes = cs_disasm(*csa_cookie->handle, instruction_bytes,
                                    ARM64_INSTRUCTION_LENGTH, rip, 1, &insn);
  if (instructions_in_bytes != 1) {
    return NULL;
  }

  size_t disassembled_length =
      strlen(insn[0].mnemonic) + strlen(insn[0].op_str) + 2;
  char *disassembled_insn = (char *)calloc(sizeof(char), disassembled_length);

  strcat(disassembled_insn, insn[0].mnemonic);
  strcat(disassembled_insn, " ");
  strcat(disassembled_insn, insn[0].op_str);
  printf("disassembled_insn: %s\n", disassembled_insn);
  return disassembled_insn;
}
