#include <string.h>
#include <trapse/zydis.h>
#include <trapse/global.h>

bool zydis_initialize_disassembler(void *cookie) {
  ZydisCookie *z_cookie = (ZydisCookie *)cookie;
  ZydisDecoder *decoder = z_cookie->decoder;
  ZydisFormatter *formatter = z_cookie->formatter;

  ZydisDecoderInit(decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  return true;
}

char *zydis_get_instruction_disassembly(uint8_t *instruction_bytes,
                                        uint64_t rip, void *cookie) {

  const static char *DECODE_FAILURE = "---DECODE FAILURE---";
  const static int DECODE_FAILURE_LENGTH = 20 + 1;
  #define DECODED_INSTRUCTION_BUFFER_LENGTH 256

  ZydisCookie *z_cookie = (ZydisCookie *)cookie;
  ZydisDecoder *decoder = z_cookie->decoder;
  ZydisFormatter *formatter = z_cookie->formatter;

  char *ret = NULL;
  char decoded_instruction_buffer[DECODED_INSTRUCTION_BUFFER_LENGTH] = {};

  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

  if (ZYAN_FAILED((ZydisDecoderDecodeFull(
          decoder, instruction_bytes, LARGEST_X86_64_INSTR, &instruction,
          operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
          ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))) {
    strncpy(decoded_instruction_buffer, DECODE_FAILURE, DECODE_FAILURE_LENGTH);
  }

  if (ZYAN_FAILED(ZydisFormatterFormatInstruction(
          formatter, &instruction, operands, instruction.operand_count_visible,
          decoded_instruction_buffer, sizeof(decoded_instruction_buffer),
          rip))) {
    strncpy(decoded_instruction_buffer, DECODE_FAILURE, DECODE_FAILURE_LENGTH);
  }

  // Do a fixed-size calloc(3) -- it'll be faster to use a little extra memory
  // rather than call strlen to find the exact size.
  ret = (char *)calloc(DECODED_INSTRUCTION_BUFFER_LENGTH, sizeof(char));
  strncat(ret, decoded_instruction_buffer, DECODED_INSTRUCTION_BUFFER_LENGTH);

  return ret;
}