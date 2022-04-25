#ifndef _TRAPSE_SUPPORT_H
#define _TRAPSE_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  char *executable_name;
  _Bool debug;
  _Bool show_registers;
} Configuration;

_Bool parse_configuration(int argc, char *argv[], Configuration *config);

void usage(char *invocation);

void print_instruction_bytes(uint8_t *instruction_bytes);

// Plug and play disassemblers as long as they can adhere to this interface!
typedef struct {
  _Bool (*initializer)(void *);
  char *(*disassemble)(uint8_t *, uint64_t, void *);
  void *cookie;

} DisassemblerConfiguration;

#if defined WINX86
#include <Windows.h>

LPSTR win_strerror_create(DWORD errorID);
void win_strerror_free(LPSTR to_free);
#endif

#endif // _TRAPSE_SUPPORT_H
