#include <stdbool.h>
#include <stdint.h>
#include <trapse/global.h>
#include <trapse/support.h>

_Bool parse_configuration(int argc, char *argv[], Configuration *config) {
  if (argc < 2 || argc > 3) {
    config->executable_name = NULL;
    return false;
  }
  config->executable_name = argv[1];

  config->show_registers = (argc > 2 && !strcmp(argv[2], "--registers"));

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

