from pwn import *

io = remote("the-final-countdown--shawn-mendes-3474.ctf.kitctf.de", "443", ssl=True)
data = open("moves.txt").read()
io.sendlineafter(b"EOF\n", data.encode())
io.interactive()

"""
You solved the challenge, here is your flag:
GPNCTF{p41n_70_d3v3l0p_h0p3fully_l355_p41n_70_50lv3_fd29a4b2833}
"""