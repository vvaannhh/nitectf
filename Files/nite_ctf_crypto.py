# never stop exploit
# challenge Rabin to the rescue
from Crypto.Util.number import *
from pwn import *


def is_sqrt(number):
    x = number
    y = (x + number // x) // 2
    while y < x:
        x = y
        y = (x + number // x) // 2
    return x


def isqrt(n):
    return int(n ** 0.5)


def fermat(n, verbose=False):
    a = is_sqrt(n)
    b2 = a ** 2 - n
    b = isqrt(n)
    count = 0
    while b ** 2 != b2:
        if verbose:
            print("%s. Trying: a=%s b2=%s b=%s" % (count, a, b2, b))
        a += 1
        b2 = a ** 2 - n
        b = isqrt(b2)
        count += 1
    p = a + b
    q = a - b
    assert n == p * q
    return p, q


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(
            lastremainder, remainder
        )
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


req = remote("rabin.challenge.cryptonite.team", 1337)
req.sendline(b"G")
req.recvuntil(b"Your encrypted flag is:\n")
enc_flag = req.recvline().strip()
enc_flag = int(enc_flag, 16)
print("enc_flag =", enc_flag)
t = False
i = 1
test = []
while not t:
    print("i =", i)
    req.sendline(b"E")
    message = "test" * i
    req.sendline(message.encode().hex().encode())
    req.recvuntil(b"Your Ciphertext is: \n")
    cipher = req.recvline().strip()
    if bytes_to_long(message.encode()) ** 2 > int(cipher, 16):
        order = i
        test.append({bytes_to_long(message.encode()), int(cipher, 16)})
        t = True
    else:
        i += 1

found = False
i = 1
n = 0
while not found:
    try:
        print("i =", i)
        req.sendline(b"E")
        message = "test" * (order + i)
        req.sendline(message.encode().hex().encode())
        req.recvuntil(b"Your Ciphertext is: \n")
        cipher = req.recvline().strip()
        test.append({bytes_to_long(message.encode()), int(cipher, 16)})
        m1, c1 = test[0]
        m2, c2 = test[len(test) - 1]
        modulus = GCD(pow(int(m1), 2) - int(c1), pow(int(m2), 2) - int(c2))
        if (m2 ** 2 % modulus) == int(c2) and (int(m1) ** 2 % modulus) == int(c1):
            n = modulus
            found = True
            print("[*] Modulus recovered:", n)
        i += 1
    except:
        req = remote("rabin.challenge.cryptonite.team", 1337)

print("n =", n)
p, q = fermat(n)
print(p * q == n and isPrime(q) and isPrime(q) and p % 4 == 3 and q % 4 == 3)
mp = pow(enc_flag, (p + 1) // 4, p)
mq = pow(enc_flag, (q + 1) // 4, q)
g, yp, yq = extended_gcd(p, q)
r = (yp * p * mq + yq * q * mp) % n
mr = n - r
s = (yp * p * mq - yq * q * mp) % n
ms = n - s
for num in [r, mr, s, ms]:
    print(long_to_bytes(num))
# nite{r3p34t3d_r461n_3ncrypt10n_l1tr4lly_k1ll5_3d6f4adc5e}


#challenge Variablezz

cipher = [
    8194393930139798,
    7130326565974613,
    9604891888210928,
    6348662706560873,
    11444688343062563,
    7335285885849258,
    3791814454530873,
    926264016764633,
    9604891888210928,
    5286663580435343,
    5801472714696338,
    875157765441840,
    926264016764633,
    2406927753242613,
    5980222734708251,
    5286663580435343,
    2822500611304865,
    5626320567751485,
    3660106045179536,
    2309834531980460,
    12010406743573553,
]
# solving using sagemath
# x=ord('n')
# y=ord('i')
# z=ord('t')
# t=ord('e')
# m = Matrix([[pow(x, 3), pow(x, 2), x, 1], [pow(y, 3),
#            pow(y, 2), y, 1], [pow(z, 3), pow(z, 2), z, 1], [pow(t, 3), pow(t, 2), t, 1]])
# v=vector([cipher[0],cipher[1],cipher[2],cipher[3]])
# print(m.solve_right(v))
a, b, c, d = 6096359484, 6606845234, 1736000027, 5669601428
flag = "nite"
import string

for j in range(4, len(cipher)):
    for i in string.printable:
        res = a * pow(ord(i), 3) + b * pow(ord(i), 2) + c * ord(i) + d
        if res == cipher[j]:
            flag += i
            break
print(flag)
# nite{jU5t_b45Ic_MaTH}


#challenge Flip me over

from pwn import *
from binascii import *
from Crypto.Util.number import *

r = remote("flipmeover.chall.cryptonite.team", 1337)
sendstr = b"a" * 39 + b"gimmeflaa"
r.recvuntil(b"Enter username in hex():\n")
r.sendline(sendstr.hex().encode())
token = r.recvline().strip()
tag = token[:32]
cipher = token[32:]
blocks = []
for i in range(32, len(token), 32):
    blocks.append(list(unhexlify(token[i : i + 32])))
for i in range(0, 256):
    print("[+] Try i =",i)
    blocks[1][15] = i
    r.recvuntil(b"Enter token in hex():\n")
    new_token = b""
    for j in range(len(blocks)):
        for k in range(len(blocks[j])):
            new_token += long_to_bytes(blocks[j][k])
    new_token = tag + new_token.hex().encode()
    r.sendline(new_token)
    r.recvuntil(b"Enter tag in hex():\n")
    r.sendline(tag)
    tmp = r.recvline().strip().decode()
    if tmp == "Oh no u flipped me...":
        r.interactive()
    r.recvuntil(b"Is your username ")
    x = r.recvline().strip()
    x = unhexlify(x)
    print(x)
    print()

# nite{flippity_floppity_congrats_you're_a_nerd}
