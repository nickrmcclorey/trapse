#include <stdio.h>
#include <stdbool.h>

typedef struct {
  char *executable_name;
} Configuration;

_Bool parse_configuration(int argc, char *argv[], Configuration *config) {
  if (argc != 2) {
    config->executable_name = NULL;
    return false;
  }
  config->executable_name = argv[1];
  return true;
}

void usage(char *invocation) {
  printf("Usage: %s <executable>\n", invocation);
}

int main(int argc, char *argv[]) {

  Configuration config = {};
  if (!parse_configuration(argc, argv, &config)) {
    usage(argv[0]);
    return 1;
  }

  return 0;
}