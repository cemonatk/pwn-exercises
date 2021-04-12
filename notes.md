# Some Random Notes

Let me put them here by now, I'll take care later on if needed.


## 1. Linux Commands

**Command to check latest segfault etc:**
$ dmesg | tail

**Some other useful tools:**
```
ldd

strings

readelf
```

Terminal command to compile with debug symbols + without pie + without ASLR + for x86:

```js
gcc -o 1 1.c -z execstack -fno-stack-protector -m32 -no-pie -g
``` 

### Disassembling

```
objdump -d ./x  -M intel

objdump -S x -M intel | grep "xor    eax,eax" -A 3 | grep ret -B 3
```

### Output to be piped into the binary

```py
python2 -c 'print "A"*16 + "\xaa\xaa\xaa\xaa"' | ./binary
```

```bash
echo "xxxx" | ./binary
```

 
## 2. GDB-Peda && pwntools

### 2.1 GDB:

#### 2.1.1 Using Macro:

```x86asm
define hook-stop
>i r
>x/x *0x00000
>end 
```

```x86asm
command
>i r
>x/x *0x00000
>end 
```

#### 2.1.2 py-gdb scripting:

* Usage1: gdb -q -x test.py
* Usage2: in gdb; source test.py 

```py
import gdb
gdb.execute('file 0')
o = gdb.execute('disas main', to_string=True)
print(o)
gdb.execute('quit')
```
#### 2.1.3 Several useful commands

```x86asm
gdb -q ./ss

disp/5i $pc

set disassembly-flavor intel

b *0x080491d6
b funcname
b funcname+5
b 15 ->> line no.

i b  / info breakpoints
del 2
del  / deletes all breakpoints

i r esp ebp

x/s XXXXXx

x/x $esp

x/30x $esp

r < $(python2 -c 'print "a"*32 + "\xaa\xaa\xaa\xaa"')
r <<< $(python2 -c 'print "aa"*65')
r $(python2 -c 'print "\x90"*64 + "\x64\x63\x62\x61"')

info functions / i functions

print modified / variable name

info proc mappings

vmmap

set $eax=0xff


(gdb) set variable i = 20
(gdb) p i
$1 = 20

(gdb) p &i
$2 = (int *) 0xffffffff
(gdb) set *((int *) 0xffffffff) = 10
(gdb) p i
$3 = 10

(gdb) set {int}0x0ffffff = 0xffffffff

```
 
### 2.2 peda:

```
pset option debug on

shellcode generate x86/linux exec

pattern arg 100

pattern offset AdA

pattern offset $pc

info address win

xrefs

ropsearch

ropgadget 

dumprop
```

#### stack dump:
```
telescope 20
```

pset env GREENIE aaaaaaaaaaaaaa



### 2.3 pwntools

TO-DO

## 3. x86 assembly && shellcoding


**"lea" Instruction:**
```x86asm
lea eax, [esp+0x1c] 
does ;
eax = esp+0x1c
```

>like mov command but instead of moving the content of an register offset into a register, it moves the address of an register offset into a register.

**Other junkie info

```x86asm
xor eax, eax; this is for reset eax in case something is there (i.e; null-byte)


//bin/sh || /bin//sh -> 8 bytes so it fits well in x86


```

**ret val**
```nasm
mov eax, value 
leave
ret ; may need to clean up stack
```


**local variables**
```nasm
[ebp-0xN]  or  [esp+0xN]
```

**function args:**
```nasm
[ebp+0x8 + 4*index]

Argv[0] => [ebp+0x8]
```

Pushed onto stack from right to left.

**Calling Conventions:**

TO-DO:

Add more info && explanation.

```
prologue:
 save current state (registers etc: push ebp; mov ebp, esp )
 create memory for function
 
epilogue:
	return values 
	restore previous state (registers etc: mov esp ebp; pop ebp)
```


Useful Resources:

1. [Linux x86 Program Start Up or - How the heck do we get to main()? by Patrick Horgan](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)
2. [https://www.amazon.de/-/en/Bruce-Dang/dp/1118787315](https://www.amazon.de/-/en/Bruce-Dang/dp/1118787315)
3. https://www.iecc.com/linker/
4. https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html
5. https://www.airs.com/blog/archives/38
