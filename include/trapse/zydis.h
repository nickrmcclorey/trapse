#ifndef TRAPSE_ZYDIS_H
#define TRAPSE_ZYDIS_H
#include "Zycore/Status.h"
#include "Zydis/DecoderTypes.h"
#include "Zydis/Formatter.h"
#include <Zydis/SharedTypes.h>
#include <Zydis/Zydis.h>
#include <stdbool.h>

// Functions for using the Zydis disassembler.
typedef struct {
  ZydisDecoder *decoder;
  ZydisFormatter *formatter;
} ZydisCookie;

bool zydis_initialize_disassembler(void *cookie);

char *zydis_get_instruction_disassembly(uint8_t *instruction_bytes,
                                        uint64_t rip, void *cookie);

#endif // TRAPSE_ZYDIS_H