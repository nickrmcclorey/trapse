#include <trapse/os.h>

extern char **environ;

// Operational support functions.
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

_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes) {
  // Now, let's try to get the instruction's bytes!

  // Clear errno -- because the return value of the next four calls to
  // ptrace(3) return the value fetch (and not a status value), then a changed
  // errno is the only signal we have that something went wrong.
  errno = 0;

  *((uint32_t *)(&(instruction_bytes[0]))) =
      ptrace(PTRACE_PEEKDATA, trapsee_pid, rip, NULL); // (4 bytes)
  *((uint32_t *)(&(instruction_bytes[sizeof(uint32_t) * 1]))) =
      ptrace(PTRACE_PEEKDATA, trapsee_pid, rip + sizeof(uint32_t) * 1,
             NULL); // (4 bytes)
  *((uint32_t *)(&(instruction_bytes[sizeof(uint32_t) * 2]))) =
      ptrace(PTRACE_PEEKDATA, trapsee_pid, rip + sizeof(uint32_t) * 2,
             NULL); // (4 bytes)
  *((uint32_t *)(&(instruction_bytes[sizeof(uint32_t) * 3]))) =
      ptrace(PTRACE_PEEKDATA, trapsee_pid, rip + sizeof(uint32_t) * 3,
             NULL); // (4 bytes)
  return errno == 0;
}
