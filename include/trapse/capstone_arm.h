#ifndef TRAPSE_CAPSTONE_ARM_H
#define TRAPSE_CAPSTONE_ARM_H

#include <capstone/capstone.h>

#define ARM64_INSTRUCTION_LENGTH 8
// Functions for using the Capstone-Arm disassembler.
typedef struct {
  csh *handle;
} CapstoneArmCookie;

_Bool capstone_arm_initialize_disassembler(void *cookie);

char *capstone_arm_get_instruction_disassembly(uint8_t *instruction_bytes,
                                               uint64_t rip, void *cookie);

#endif // TRAPSE_CAPSTONE_ARM_H
