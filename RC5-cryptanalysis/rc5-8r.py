#8-round RC5-32/16/16 without any rotations.

import ctypes

w = 32
r = 8
b = 16
c = 8*b/w
t = 2*(r+1)    #size of table
s = [0 for i in range(t)]    #expanded key table
P = 0xb7e15163
Q = 0x9e3779b9

def encryption(pt,ct):
    A = ctypes.c_ulong(pt[0] + s[0]).value
    B = ctypes.c_ulong(pt[1] + s[1]).value
    for i in range(1, r+1):
        A = ctypes.c_ulong(A^B).value + ctypes.c_ulong(s[2 * i]).value
        B = ctypes.c_ulong(B^A).value + ctypes.c_ulong(s[2 * i + 1]).value
    ct[0] = ctypes.c_ulong(A).value
    ct[1] = ctypes.c_ulong(B).value

def decryption(pt,ct):
    A = ctypes.c_ulong(ct[0]).value
    B = ctypes.c_ulong(ct[1]).value
    for i in range(r):
        i = r - i
        B = ctypes.c_ulong((B-s[2*i+1])^A).value
        A = ctypes.c_ulong((A-s[2*i])^B).value
    pt[1] = ctypes.c_ulong(B - s[1]).value
    pt[0] = ctypes.c_ulong(A - s[0]).value

def setup(k):
    u = w/8
    l = [k[i] for i in range(c)]
    s[0] = ctypes.c_ulong(P).value
    for i in range(1,t):
        s[i] = ctypes.c_ulong(s[i-1] + Q).value
    A = B = x = y = 0
    for i in range(3*t):
        A = s[x] = ctypes.c_ulong(s[x]+(A+B)).value
        B = l[y] = ctypes.c_ulong(l[y]+(A+B)).value
        x = (x+1) % t
        y = (y+1) % c

def main():
    pt = [0,0]
    key = [0 for i in range(c)]
    ct = [0,0]
    setup(key)
    encryption(pt,ct)
    print ("key="),
    for j in range(c):
        print ("%.8X" %key[j]),
    print ("\nplaintext  %.8X %.8X" % (pt[0],pt[1])),
    print ("\nciphertext %.8X %.8X" % (ct[0], ct[1]))
    decryption(pt,ct)
    print ("DEC : %.8X %.8X " % (pt[0], pt[1]))

if __name__ == '__main__':
    main()