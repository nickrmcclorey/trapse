#include <trapse/os.h>

extern char **environ;

#if defined MACOSX || defined LINUX
_Noreturn void exit_because(int err, pid_t trapsee_pid) {
  fprintf(stderr, "Exiting because: %s\n", strerror(err));
  fprintf(stderr, "Stopping ...\n");
  if (trapsee_pid != 0 && kill(trapsee_pid, SIGKILL)) {
    fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(err));
    fprintf(stderr, "Ignoring and still stopping ...\n");
  }
#else
_Noreturn void exit_because(int err, DWORD trapsee_pid) {
  LPSTR error_string = win_strerror_create(err);
  fprintf(stderr, "Exiting because: %s\n", error_string);
  win_strerror_free(error_string);

  if (trapsee_pid != 0) {
    HANDLE trapsee_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, trapsee_pid);
    if (trapsee_handle == NULL || !TerminateProcess(trapsee_handle, 1)) {
      LPSTR error_string = win_strerror_create(GetLastError());
      fprintf(stderr, "Failed to kill the trapsee: %s\n", strerror(err));
      fprintf(stderr, "Ignoring and still stopping ...\n");
      win_strerror_free(error_string);
    }
  }
#endif
  exit(1);
}

#if defined WINX86
bool set_singlestep(HANDLE *thread_handle) {
  CONTEXT threadContext;
  memset(&threadContext, 0, sizeof(CONTEXT));
  threadContext.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(*thread_handle, &threadContext)) {
    return false;
  }
  threadContext.EFlags |= 0x100;
  threadContext.ContextFlags = CONTEXT_FULL;
  if (!SetThreadContext(*thread_handle, &threadContext)) {
    return false;
  }
  return true;
}

uint64_t get_rip(HANDLE *thread_handle, uint64_t *rip) {
  CONTEXT threadContext;
  memset(&threadContext, 0, sizeof(CONTEXT));
  threadContext.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(*thread_handle, &threadContext)) {
    return false;
  }
  *rip = threadContext.Rip;
  return true;
}
#endif

// Operational support functions.
#if defined MACOSX || defined LINUX
bool spawn(pid_t *child, char *trapsee_path, bool debug) {
#else
_Bool spawn(DWORD *child, char *trapsee_path, bool debug) {
#endif
#if defined MACOSX || defined LINUX
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
#else
  // Windows
  LPSTR trapsee_commandline = NULL;

  PROCESS_INFORMATION trapsee_processinformation;
  STARTUPINFO trapsee_processstartupinfo;

  memset(&trapsee_processinformation, 0, sizeof(PROCESS_INFORMATION));
  memset(&trapsee_processstartupinfo, 0, sizeof(STARTUPINFO));

  bool create_result =
      CreateProcessA(trapsee_path, trapsee_commandline, NULL, NULL, FALSE,
                     /*CREATE_SUSPENDED | */ DEBUG_PROCESS, NULL, NULL,
                     (LPSTARTUPINFOA)(&trapsee_processstartupinfo),
                     &trapsee_processinformation);

  if (!create_result) {
    errno = GetLastError();
    LPSTR error_string = win_strerror_create(errno);
    fprintf(stderr, "Error CreateProcessA trapsee: %s\n", error_string);
    win_strerror_free(error_string);
    return false;
  }
  if (debug) {
    printf("Successfully CreateProcessA()\n");
  }

  *child = trapsee_processinformation.dwProcessId;
#endif
  return true;
}

#if defined MACOSX || defined LINUX
_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes) {
#elif defined WINX86
_Bool get_instruction_bytes(DWORD trapsee_pid, uint64_t address,
                            uint8_t *instruction_bytes) {
#endif
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
#elif defined WINX86
HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, trapsee_pid);
if (process_handle == 0) {
  errno = GetLastError();
  return false;
}
size_t len_read = 0;
if (ReadProcessMemory(process_handle, (LPCVOID)address, instruction_bytes,
                      LARGEST_X86_64_INSTR, &len_read) &&
    len_read == LARGEST_X86_64_INSTR) {
  return true;
}
errno = GetLastError();
return false;
#else
return false;
#endif
}
