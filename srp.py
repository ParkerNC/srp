from random import randrange
from random import getrandbits

from Crypto.Cipher import AES

from Crypto.Hash import SHA256

def fastexp(b: int, e: int, n: int) -> int:
    #part 1 fast modular exponentiation
    prod = 1
    base = b
    exp = bin(e)[::-1]
    exp = exp[:-2]
    for bit in exp:
        if bit == "1":
            prod = (prod * base) %n
        
        base = (base * base ) %n

    return prod

def gToA(p: int, g: int, a: int) -> int:
    pKey = fastexp(g, a, p)

    return pKey

def hexToByte(hex: str) -> bytes:
    bitHex = int(hex, 16)

    bitHex = bitHex.to_bytes((bitHex.bit_length() + 7) // 8, 'big') or b'\0'

    return bitHex

def strToByte(word: str):

    byteWord = bytes(word, 'utf-8')

    return byteWord

def griddle(salt: bytes, password: bytes, hashNum: int) -> int:
    shredded = salt + password
    
    hashBrown = SHA256.new(shredded)

    for i in range(hashNum-1):
        hashBrown = SHA256.new(hashBrown.digest())

    return (int.from_bytes(hashBrown.digest(), "big"))

def toast(p: int, g: int) -> int:
    bitP = p.to_bytes((p.bit_length() + 7) // 8, 'big') or b'\0'
    bitG = g.to_bytes((g.bit_length() + 7) // 8, 'big') or b'\0'

    butter = bitP + bitG

    k = SHA256.new(butter)

    return (int.from_bytes(k.digest(), "big")) 

def scramble(B: int, k: int, g: int, x: int, p: int) -> int:

    pubKey = B - k * fastexp(g, x, p)

    return pubKey % p

def bacon (pubKey: int, a: int, u: int, x: int, p) -> int:
    grease = a + (u * x)

    return fastexp(pubKey, grease, p)

def allStarSpecial (p: int, g: int, netId: str, salt: str, myPubKey: int, outPubKey: int, sharedKey: int) -> bytes:
    bP = p.to_bytes((p.bit_length() + 7) // 8, "big") or b'\0'
    bG = g.to_bytes((g.bit_length() + 7) // 8, "big") or b'\0'
    shaP = SHA256.new(bP)
    shaG = SHA256.new(bG)

    byteP = int.from_bytes(shaP.digest(), "big")
    byteG = int.from_bytes(shaG.digest(), "big")

    xorHash = byteP ^ byteG

    xHash = xorHash.to_bytes((xorHash.bit_length() + 7) // 8, "big") or b'\0'

    hId = SHA256.new(strToByte(netId)).digest()

    bMyKey = myPubKey.to_bytes((myPubKey.bit_length() + 7) // 8, "big") or b'\0'
    bOutKey = outPubKey.to_bytes((outPubKey.bit_length() + 7) // 8, "big") or b'\0'
    bShareKey = sharedKey.to_bytes((sharedKey.bit_length() + 7) // 8, "big") or b'\0'

    bitSalt = hexToByte(salt)

    plate = xHash + hId + bitSalt + bMyKey + bOutKey + bShareKey

    cooked = SHA256.new(plate)
    print(cooked.hexdigest())

    return(cooked.digest())

def coffee (myKey: int, m1: bytes, sharedKey: int) -> str:
    bMyKey = myKey.to_bytes((myKey.bit_length() + 7) // 8, "big") or b'\0'
    bShareKey = sharedKey.to_bytes((sharedKey.bit_length() + 7) // 8, "big") or b'\0'

    grounds = bMyKey + m1 + bShareKey

    cup = SHA256.new(grounds)

    return cup.hexdigest()

def main():

    #aGen = randrange(1024)

    #print(aGen)

    a = 253

    g = 5

    p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407

    #pubKey = gToA(p, g, a)
    #print(pubKey)

    myPubKey = 690893484407555570030908149024031965689280029154902510801896277613487344252994164637720600277783058124843783515691973087759607915746555735492240302164645981974899768829345703125

    B = 43983819761592108008038567027723966762484381893165687326937524110129708181329942650448899923174224740357424545738423348017194763962147097702415276137801553842757954090495942811191913324500861819985048732500354969146488167948672118990155814073007507645634964135044539153097221347901536747984347542208458246729
    
    iterations = 1000

    Salt = "234e810a"

    Pass = "picaninny"

    User = "pcollie4"

    saltBytes = hexToByte(Salt)

    passBytes = strToByte(Pass)

    x = griddle(saltBytes, passBytes, iterations)

    k = toast(p, g)

    outPubKey = scramble(B, k, g, x, p)

    u = toast(myPubKey, outPubKey)

    sharedKey = bacon(outPubKey, a, u, x, p)

    M1 = allStarSpecial(p, g, User, Salt, myPubKey, outPubKey, sharedKey)

    M2 = coffee(myPubKey, M1, sharedKey)

    print(M2)

if __name__ == "__main__":
    main()