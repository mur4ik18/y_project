    .section __TEXT,__text,regular,pure_instructions
    .globl _main                   // Export the entry point to the linker
    .align 2                       // Align the next instruction on a 4-byte boundary

_main:                             // The program's entry point
    // Write "Hello, World!" to stdout
    mov x0, #1                     // File descriptor 1 is stdout
    ldr x1, =message               // Load address of the message
    mov x2, #13                    // Length of the message
    mov x16, #0x20                 // macOS syscall for write
    svc #0                         // Make the syscall

    // Exit the program
    mov x0, #0                     // Exit code 0
    mov x16, #0x1                  // macOS syscall for exit
    svc #0                         // Make the syscall

    .section __TEXT,__cstring
message:
    .asciz "Hello, World!\n"       // Null-terminated string
