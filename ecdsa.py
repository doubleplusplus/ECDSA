import hashlib


def x_gcd(a, b): # extended GCD
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

# multiplicative inverse mod n
def mod_inv(a, n):
    g, x, y = x_gcd(a, n)
    if g != 1:
        raise ValueError(f'mod_inv for {a} does not exist')
    return x % n

def get_s(a, p, x1, x2, y1, y2):
    if x1 == x2 and y1 == y2:
        s = ((x1**2 * 3 + a ) * mod_inv(2 * y1, p)) % p
    else:
        de = x2 - x1
        while de < 0:
            de += p
        s = ((y2 - y1) * mod_inv(de, p)) % p
    #print('s =', s)
    return s

def verify(x, y, a, b, p):
    return (y**2 % p) == ((x**3 + a * x + b) % p)

def elli_add(a, p, x1, y1, x2, y2):
    if (-y1) % p == y2 and x1 == x2:  # neutral element
        return 'neutral', 'element'
    else:
        s = get_s(a, p, x1, x2, y1, y2)
        x3 = (s ** 2 - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return x3, y3

def double_and_add(a, p, x, y, n):
    d = bin(n)[3:]  # remove '0b', start from the second bit
    xt, yt = x, y
    for i in d:
        xt, yt = elli_add(a, p, xt, yt, xt, yt)
        if i == '1':
            xt, yt = elli_add(a, p, xt, yt, x, y)
    return xt, yt

p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151

q = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449

a = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148

#b = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984

A = ( 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846,
      3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784)

d = 0x2F65EBED733DA759529E5AF059C0FE8A35536BAFDC0862C2893859D840416A44B35F2A564A1E6C3D57186BEDC6F3E749444033FF54872C9A9BE6EF07A4A7928CF6

k_E = 0x01349ea8729cde0bbade38204e63359a46e672a8d0a2fd5300692ab48f9ef732f5c3fa212b90c98229bbb79bece734a622154c904dce9a0f53d4a88b3e558ef76131

def ecdsa():
    ms = 'This is a test!'
    bytestring = bytes(ms, 'utf-8')
    h = hashlib.sha3_512(bytestring).hexdigest()
    hx = int(h, 16)
    # b = ( bin(int(h, 16))[2:] ).zfill(521)
    B = double_and_add(a, p, A[0], A[1], d)
    print('B =', B)

    "Signature generation"
    R = double_and_add(a, p, A[0], A[1], k_E)
    r = R[0]
    s = ((hx + d * r) * mod_inv(k_E, q)) % q
    print('s =', hex(s))

    "Signature verification"
    w = mod_inv(s, q) % q
    u1 = (w * hx) % q
    u2 = (w * r) % q
    u1A = double_and_add(a, p, A[0], A[1], u1)
    u2B = double_and_add(a, p, B[0], B[1], u2)
    P = elli_add(a, p, u1A[0], u1A[1], u2B[0], u2B[1])
    print('verify signature:', P[0] % q == r % q)

def message():
    r1 = 0x0127c8f66638a0c61c37944b615f596cd2ebee1aae6a493795ba2e27246d75b02e65e6a2e9f395eb17057989a85393ac5be170ce94594493ca8b5e941a3f28d1c6b3
    s1 = 0x00a7bc3e4e817bbd276f62bc8e354df9049b289899ecd22a405ec3e2cdd63006052bc227dbb03e8a4d59b6b86ba420a60f79be4af9476e2854d0f8dc3a6d2eae674e

    k_ep = 0x7518f204fe6846aeb6f58174d57a3372363c0d9fcfaa3dc18b1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca876

    ms = 'Y!'
    print(ms)
    bytestring1 = bytes(ms, 'ascii')
    h1 = hashlib.sha3_512(bytestring1).hexdigest()
    hx1 = int(h1, 16)
    s_new = ((hx1 + d * r1) * mod_inv(k_ep, q)) % q
    print('s_new =', s_new == s1)


#ecdsa()
message()


def leakage():
    # first message
    r1 = 0x0069c695c87973520fa07eb5eef4846d4e2405dbd175550ef858577555b73dc8a60fc221322c37b6ffe49db901121063e36b43aa9936703425c78ccf3fafa27bc566
    s1 = 0x010e54d7d2e48ea6f907cb51e6d7de460ee26ec35d19c36e7107ccb1f72160f0660a6dae3fb31b3c0c02638431c697ea488ff97af387a4384a67071696207167d440
    # second message
    r2 = 0x0069c695c87973520fa07eb5eef4846d4e2405dbd175550ef858577555b73dc8a60fc221322c37b6ffe49db901121063e36b43aa9936703425c78ccf3fafa27bc566
    s2 = 0x008ff6d18d59dbc4911cdaaae47ff7b4151cbe103c46b3b6f880d5b1aeedd4aa59dc036db5ff2956cb9f65b3cc1a2390f9d01977c73bde9676c440b53163902dd332
    #print(r1 == r2)
    ms1 = 'Message1'
    ms2 = 'Message2'
    bs1 = bytes(ms1, 'utf-8')
    h1 = hashlib.sha3_512(bs1).hexdigest()
    hm1 = int(h1, 16)

    bs2 = bytes(ms2, 'utf-8')
    h2 = hashlib.sha3_512(bs2).hexdigest()
    hm2 = int(h2, 16)

    k_E = ((hm1 - hm2) * mod_inv(s1 - s2, q)) % q
    print('k_E =', hex(k_E))
    d = ((s1 * k_E - hm1) * mod_inv(r1, q)) % q
    print('d =', hex(d))

    print("verify key")
    R = double_and_add(a, p, A[0], A[1], k_E)
    r = R[0]
    s = ((hm2 + d * r) * mod_inv(k_E, q)) % q
    print(r == r1, s == s2)


#leakage()
