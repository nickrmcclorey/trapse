#ifndef TRAPSE_OS_H
#define TRAPSE_OS_H

#if defined MACOSX86
#include <mach/mach.h>
#include <sys/errno.h>
#elif defined WINX86
#include <errno.h>
#else
#include <errno.h>
#include <error.h>
#endif

#if defined WINX86
#include <Windows.h>
#endif

#if defined LINUX
#include <linux/unistd.h>
#include <sys/personality.h>
#endif

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined MACOSX || defined LINUX
#include <sys/ptrace.h>
#endif
#include <sys/types.h>
#if defined MACOSX || defined LINUX
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <trapse/global.h>
#include <trapse/support.h>

#if defined MACOSX || defined LINUX
void exit_because(int err, pid_t trapsee_pid);
#else
void exit_because(int err, DWORD trapsee_pid);
#endif
#if defined MACOSX || defined LINUX
bool spawn(pid_t *child, char *trapsee_path, bool debug);
#else
_Bool spawn(DWORD *child, char *trapsee_path, bool debug);
#endif

#if defined MACOSX || defined LINUX
_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes);
#else
_Bool get_instruction_bytes(DWORD trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes);
#endif


#if defined WINX86
bool set_singlestep(HANDLE* thread_handle);
uint64_t get_rip(HANDLE* thread_handle, uint64_t* rip);
#endif
#endif // TRAPSE_OS_H
