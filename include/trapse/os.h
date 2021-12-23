#ifndef TRAPSE_OS_H
#define TRAPSE_OS_H

#ifdef MACOSX86
#include <mach/mach.h>
#include <sys/errno.h>
#else
#include <errno.h>
#include <error.h>
#endif

#ifndef MACOSX86
#include <linux/unistd.h>
#include <sys/personality.h>
#endif

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <trapse/global.h>

void exit_because(int err, pid_t trapsee_pid);

bool spawn(pid_t *child, char *trapsee_path, bool debug);

_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes);
#endif // TRAPSE_OS_H
