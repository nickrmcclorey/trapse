#include <trapse/os.h>

extern char **environ;

_Noreturn void exit_because(int err, pid_t trapsee_pid) {
  fprintf(stderr, "Failed to get the registers: %s\n", strerror(err));
  fprintf(stderr, "Stopping ...\n");
  if (kill(trapsee_pid, SIGKILL)) {
    fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(err));
    fprintf(stderr, "Ignoring and still stopping ...\n");
  }
  exit(1);
}

// Operational support functions.
bool spawn(pid_t *child, char *trapsee_path, bool debug) {
  if (!(*child = fork())) {
    char *child_argv[] = {trapsee_path, NULL};
    /*
     * We are in the child.
     */
#ifdef LINUX
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
#elif MACOSX86
    ptrace(PT_TRACE_ME, 0, NULL, NULL);
#else
    exit(1);
#endif

#ifdef LINUX
    // TODO (hawkinsw): Temporarily disable ASLR.
    personality(ADDR_NO_RANDOMIZE);
#endif

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

  if (debug) {
    printf("Spawned trapsee with PID: %d\n", *child);
  }

  return true;
}

_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes) {

  // Clear errno -- because the return value of the next four calls to
  // ptrace(3) return the value fetch (and not a status value), then a changed
  // errno is the only signal we have that something went wrong.

  errno = 0;

#ifdef LINUX
  // Now, let's try to get the instruction's bytes (on Linux)!

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
#elif MACOSX86
  kern_return_t mach_call_result = false;
  mach_port_t port;
  mach_msg_type_number_t bytes_read_len = 0;
  vm_offset_t bytes_read;

  if (KERN_SUCCESS !=
      (mach_call_result = task_for_pid(mach_task_self(), trapsee_pid, &port))) {
    errno = mach_call_result;
    return false;
  }
  if (KERN_SUCCESS !=
      (mach_call_result = vm_read(port, (vm_address_t)rip, LARGEST_X86_64_INSTR,
                                  &bytes_read, &bytes_read_len))) {
    errno = mach_call_result;
    return false;
  }
  memcpy(instruction_bytes, (const void *)bytes_read, bytes_read_len);
  if (KERN_SUCCESS != (mach_call_result = vm_deallocate(
                           mach_task_self(), bytes_read, bytes_read_len))) {
    errno = mach_call_result;
    return false;
  }
  return true;
#else
  return false;
#endif
}
