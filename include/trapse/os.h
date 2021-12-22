#ifndef TRAPSE_OS_H
#define TRAPSE_OS_H
#include <errno.h>
#include <error.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>

bool spawn(pid_t *child, char *trapsee_path);

_Bool get_instruction_bytes(pid_t trapsee_pid, uint64_t rip,
                            uint8_t *instruction_bytes);
#endif // TRAPSE_OS_H