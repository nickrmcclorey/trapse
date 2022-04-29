# Trapse
## Usage
`./trapse <executable> --registers=rax,rdx --entry --entry=0x555555555040:0x1020`

Register printing is only supported on x86 Linux currently

x86 Available registers:
- r15
- r14
- r13
- r12
- r11
- r10
- r9
- r8
- rbp
- rbx
- rax
- rcx
- rdx
- rsi
- rdi
- orig_rax
- rip
- cs
- eflags
- rsp
- ss
- fs_base
- gs_base
- ds
- es
- fs
- gs

Entry point is specified as `<entryWithOffset>:<listedEntryPoint>`

entryWithOffset is the virtual entry point when the program is actually running

listedEntryPoint is the entry point obtained from a tool like readelf or objdump. Every instruction after that will have the instruction pointer adjusted based on the offset before being printed to the screen.

Output of program is also stored in Exported.txt
