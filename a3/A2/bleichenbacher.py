import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from base64 import b64encode, b64decode
import json
import sys
import getopt

c, e, n = 0, 0, 0


def int_to_bytes(a):
    return a.to_bytes((a.bit_length() + 7) // 8, 'big')


def bytes_to_int(b):
    return int.from_bytes(b, 'big')


def base64_to_int(base64_string):
    base64_bytes = base64_string.encode('ascii')
    b = b64decode(base64_bytes)
    return bytes_to_int(b)


def int_to_base64(a):
    b = int_to_bytes(a)
    base64_bytes = b64encode(b)
    return base64_bytes.decode('ascii')


def ceildiv(a, b):
    return -(-a // b)


def floordiv(a, b):
    return a // b


server = "http://127.0.0.1:8080"
headers = {"Accept": "application/json", "Content-Type": "application/json"}


def PKCS_conform(val):
    data = {"message": int_to_base64(val)}
    j_data = json.dumps(data).encode("utf_8")
    r = requests.post(url=server, data=j_data, headers=headers)
    msg = r.json()["message"]
    if b64decode(msg).decode() == "True":
        return True
    return False

'''
def decrypt(int_cipher):
    int_plain = pow(int_cipher, d, n)
    return int_to_bytes(int_plain)
'''

def bleichenbacher():
    count = 0

    k = len(int_to_bytes(n))

    B = pow(2, 8 * (k - 2))

    i = 1
    s_i = 1
    s_prev = 1
    set_m = {(B * 2, B * 3 - 1)}
    set_m2 = set()
    while True:

        # step 2a
        if i == 1:
            s_i = n // (3 * B)
            val = c * pow(s_i, e, n) % n
            while not PKCS_conform(val):
                s_i = s_i + 1
                val = c * pow(s_i, e, n) % n
                count += 1
            count += 1
            #print("2a:", s_i)
        # step 2b
        elif i > 1 and len(set_m) > 1:
            s_i = s_prev + 1
            val = c * pow(s_i, e, n) % n
            while not PKCS_conform(val):
                count += 1
                s_i = s_i + 1
                val = c * pow(s_i, e, n) % n
            count += 1
            #print("2b:", s_i)
        # step 2c
        elif len(set_m) == 1:
            # a,b = M[0]
            a, b = next(iter(set_m))
            r_i = 2 * ((b * s_prev - 2 * B) // n)
            flag = False
            while not flag:
                low = (2 * B + r_i * n) // b
                # print("low:",low)
                high = (3 * B - 1 + r_i * n) // a
                # print("high:",high)
                for s in range(low, high + 1):
                    val = c * pow(s, e, n) % n
                    # print("2c###:",s)
                    count += 1
                    if PKCS_conform(val):
                        flag = True
                        s_i = s
                        #print("2c:", s_i)
                        break
                r_i += 1

        # step 3
        set_m2 = set()

        for a, b in set_m:
            # a, b = interval

            low = ceildiv(a * s_i - 3 * B + 1, n)
            high = floordiv(b * s_i - 2 * B, n)

            for v in (low, high + 1):
                x = (max(a, ceildiv(2 * B + v * n, s_i)))
                y = min(b, floordiv((3 * B) - 1 + v * n, s_i))

                if x <= y:
                    set_m2 |= {(x, y)}

        # for v in set_m2:
        # print(str(v))

        # step 4
        if len(set_m2) == 1:
            a, b = next(iter(set_m2))
            if a == b:
                #m = a % n
                #print("m:", m)
                # print("a:", a)
               # print("DONE!")
                #print(int_to_bytes(a))
                a = int_to_bytes(a)
                x = a.find(b'\x00')
                a = a[x+1:]
                print(a.decode())
                print(count)
                #print("This is the plain text")
                #print(a)
                return a

        i += 1
        s_prev = s_i
        set_m = set_m2
        # print("s_i:",s_i)


def main(argv):
    global c, e, n
    try:
        opts, args = getopt.getopt(argv, "hc:e:n:")
    except getopt.GetoptError:
        print('usage: bleichenbacher.py -c [path to cipher.txt] -e [path to encryption_key.txt] -n [path to modulus.txt]')
        sys.exit(1)
    for opt, arg in opts:
        if opt == '-h':
            print('usage: bleichenbacher.py -c [path to cipher.txt] -e [path to encryption_key.txt] -n [path to modulus.txt]')
            sys.exit(0)
        elif opt == '-c':
            try:
                f = open(arg, 'r')
                c = f.read()[:-1]
                #print("cipher:",c)
                c = base64_to_int(c)
            except:
                print('File Error')
                sys.exit(1)
        elif opt == '-e':
            try:
                f = open(arg, 'r')
                e = f.read()[:-1]
                #print("e:",e)
                e = base64_to_int(e)
                # print(n)
            except:
                print('File Error')
                sys.exit(1)
        elif opt == '-n':
            try:
                f = open(arg, 'r')
                n = f.read()[:-1]
               # print("n:",n)
                n = base64_to_int(n)
                # print(n)
            except:
                print('File Error')
                sys.exit(1)
    if n == 0 or e == 0 or c == 0:
        print(args)
        print('usage: bleichenbacher.py -c [path to cipher.txt] -e [path to encryption_key.txt] -n [path to modulus.txt]')
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
    bleichenbacher()
