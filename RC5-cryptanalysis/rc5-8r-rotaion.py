#8-round RC5-32/16/16 with the rotation amount equal to the round number.

import ctypes

w = 32
r = 8
b = 16
c = 8*b/w
t = 2*(r+1)
S = [0 for i in range(t)]
P = 0xb7e15163 
Q = 0x9e3779b9

def encrypt(pt, ct):
    A = ctypes.c_ulong(pt[0] + S[0]).value
    B = ctypes.c_ulong(pt[1] + S[1]).value
    for i in range(1, r+1):
        A = (((ctypes.c_ulong(A^B).value) << (ctypes.c_ulong(B).value & (w - 1))) | ((ctypes.c_ulong(A^B).value) >> (w - (ctypes.c_ulong(B).value & (w - 1))))) + ctypes.c_ulong(S[2 * i]).value
        B = (((ctypes.c_ulong(B^A).value) << (ctypes.c_ulong(A).value & (w - 1))) | ((ctypes.c_ulong(B^A).value) >> (w - (ctypes.c_ulong(A).value & (w - 1))))) + ctypes.c_ulong(S[2 * i + 1]).value
    ct[0] = ctypes.c_ulong(A).value
    ct[1] = ctypes.c_ulong(B).value
    
def decrypt(ct, pt):
    pass
    
def setup(K):
    u = w/8
    L = [0 for i in range(c)]

    for i in range(b-1, -1, -1):
        L[i / u] = (L[i / u] << 8) + K[i]
    S[0] = ctypes.c_ulong(P).value
    for i in range(1, t):
        S[i] = ctypes.c_ulong(S[i - 1] + Q).value
    A = B = i = j = 0
    for k in range(3*t):
        A = S[i] = (((ctypes.c_ulong(S[i]+(A+B)).value) << (3 & (w - 1))) | ((ctypes.c_ulong(S[i]+(A+B)).value) >> (w - (3 & (w - 1)))))
        B = L[j] = (((ctypes.c_ulong(L[j]+(A+B)).value) << ((ctypes.c_ulong(A+B)).value & (w - 1))) | ((ctypes.c_ulong(L[j]+(A+B)).value) >> (w - ((ctypes.c_ulong(A+B).value) & (w - 1)))))
        i = (i + 1) % t
        j = (j + 1) % c        
        
def main():
    pt = [0xE1202,0x45A0D]
    key = [0 for i in range(b)]
    ct = [0,0]
    setup(key)
    encrypt(pt,ct)
    print("RC5-32/8/16 with rotation:")
    print ("key="),
    for j in range(c):
        print ("%.8X" %key[j]),
    print ("\nplaintext  %.8X %.8X" % (pt[0],pt[1])),
    print ("\nciphertext %.8X %.8X" % (ct[0], ct[1]))
#    decryption(pt,ct)
#    print ("DEC : %.8X %.8X " % (pt[0], pt[1]))

        
if __name__ == '__main__':
    main()
