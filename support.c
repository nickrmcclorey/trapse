#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <trapse/global.h>
#include <trapse/support.h>


char all_registers[] = "r15,r14,r13,r12,r11,r10,r9,r8,rbp,rbx,rax,rcx,rdx,rsi,rdi,orig_rax,rip,cs,eflags,rsp,ss,fs_base,gs_base,ds,es,fs,gs";


void handleEntryArgument(char *argument, Configuration *config) {
  char *colon = strstr(argument, ":0x");
  char *equal = strstr(argument, "=0x");
  if (strstr(argument, "--entry=0x") && (colon > argument)) {
    colon += 3;
    equal += 3;
    long entry_with_offset = strtoul(equal, NULL, 16);
    long og_entry_point = strtoul(colon, NULL, 16);
    config->rip_entry = entry_with_offset;
    config->entry_offset = entry_with_offset - og_entry_point;
  }
}

void handleRegistersArgument(char *argument, Configuration *config) {
  char *equal = strstr(argument, "=");
  if (equal != NULL) {
    config->which_registers = equal + 1;
  } else {
    config->which_registers = all_registers;
  }
}

_Bool parse_configuration(int argc, char *argv[], Configuration *config) {
  if (argc < 2 || argc > 4) {
    config->executable_name = NULL;
    return false;
  }
  config->executable_name = argv[1];
  config->which_registers = NULL;
  config->rip_entry = 0;
  config->entry_offset = 0;

  for (int index = 2; argc > index; index++) {
    if (strstr(argv[index], "--registers") == argv[index]) {
      handleRegistersArgument(argv[index], config);
    } else if (strstr(argv[index], "--entry") == argv[index]) {
      handleEntryArgument(argv[index], config);
    }
  }

  config->debug = false;

  return true;
}

void usage(char *invocation) { printf("Usage: %s <executable>\n", invocation); }

void print_instruction_bytes(uint8_t *instruction_bytes) {
  for (int i = 0; i < LARGEST_X86_64_INSTR; i++) {
    printf("%hhx", instruction_bytes[i]);
  }
}

#if defined WINX86
LPSTR win_strerror_create(DWORD errorID) {
  LPSTR error_str;
  size_t error_strlen = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, errorID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&error_str, 0, NULL);

  return error_str;
}
void win_strerror_free(LPSTR to_free) { LocalFree(to_free); }
#endif

