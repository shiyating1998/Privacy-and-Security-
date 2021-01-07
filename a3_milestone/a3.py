import base64
import sys
import io
import requests
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.hash import blake2b
from nacl import pwhash, utils, secret
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder



API_TOKEN = "0110d98bbd4388d7b9727e688e843b367a23024bc04f3795f7b1d23b8c1e1291"




# Question 1 part 1: send a message [3 marks]

message = "hello Nessie"
message_bytes = message.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
base64_message = base64_bytes.decode('ascii')

print("Message sent to Nessie:" + base64_message)

# defining the api-endpoint
API_ENDPOINT = "https://hash-browns.cs.uwaterloo.ca/api/plain/send"

# data to be sent to api
data = {'url': "https://hash-browns.cs.uwaterloo.ca",
        "Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        'to': "Nessie", "message": base64_message,
        }

# sending post request and saving response as response object
r = requests.post(url=API_ENDPOINT, data=data)

# Question 1 part 2: receive a message [2 marks]
url_response = "https://hash-browns.cs.uwaterloo.ca/api/plain/inbox"
# data to be sent to api
data = {'url': "https://hash-browns.cs.uwaterloo.ca",
        "Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        }

# sending post request and saving response as response object
r = requests.post(url=url_response, data=data)

p = r.json()
# decode the message received from Nessie
base64_message = r.json()[0]['message']
base64_bytes = base64_message.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
message = message_bytes.decode('ascii')
print("The message received from Nessie in part1:" + message)




# Question 2 part 1: send a message [3 marks]
url_21 = "https://hash-browns.cs.uwaterloo.ca/api/psk/send"
message = b"hi Nessie this is encrypted"

psk = "92272236d00643e06ad67a9365d6adbe5c2b4c12c1025314f9dfcaeadae09326"
psk_binary = bytes.fromhex(psk)

box = nacl.secret.SecretBox(psk_binary)
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
encrpyted_message = box.encrypt(message, nonce)

nonce_message = nonce + encrpyted_message.ciphertext
base64_bytes = base64.b64encode(nonce_message)
base64_message = base64_bytes.decode('ascii')

data = {'url': "https://hash-browns.cs.uwaterloo.ca",
        "Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie", "message": base64_message
        }

# sending post request and saving response as response object
r = requests.post(url=url_21, data=data)


#Question 2 part 2: receive a message [2 marks]
url_22 = "https://hash-browns.cs.uwaterloo.ca/api/psk/inbox"

data = {'url': "https://hash-browns.cs.uwaterloo.ca",
        "Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        }

# sending post request and saving response as response object
r = requests.post(url=url_22, data=data)
p = r.json()
# decode the message received from Nessie
base64_message = r.json()[0]['message']
message_bytes = base64.b64decode(base64_message)
message = box.decrypt(message_bytes)
message = message.decode('utf-8')
print("The message received from Nessie in part2:" + message)



#Question 3 part 1: send a message [3 marks]

url_31 = "https://hash-browns.cs.uwaterloo.ca/api/psp/send"
message = b"q31"

password = b"sad country"
salt = bytes.fromhex("b555823b6ad309a5769096d28889b306147214e5dc7dfe1a525f9bce9dc8d11c")
script_ops_limit = 524288
script_mem_limit = 16777216

key = nacl.pwhash.scrypt.kdf(32, password, salt, script_ops_limit, script_mem_limit)

box = nacl.secret.SecretBox(key)
encrypted = box.encrypt(message)
encrypted = base64.b64encode(encrypted)
encrypted = encrypted.decode('ascii')


data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie", "message": encrypted
        }

requests.post(url_31, data=data)


#Question 3 part 2: receive a message [1 mark]
url_32 = "https://hash-browns.cs.uwaterloo.ca/api/psp/inbox"

# data to be sent to api
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        }

r = requests.post(url_32, data=data)

base64_message = r.json()[0]['message']
base64_bytes = base64_message.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
msg = box.decrypt(message_bytes)
print("The message received from Nessie in part3:",msg)



#Question 4 part 1: upload a public verification key [2 marks]

url_41 = "https://hash-browns.cs.uwaterloo.ca/api/signed/set-key"
# Generate a new random signing key
signing_key = SigningKey.generate()

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_b64 = verify_key.encode(encoder=Base64Encoder)

data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": verify_key_b64
        }

# sending post request and saving response as response object
r = requests.post(url=url_41, data=data)




#Question 4 part 2: send a message [3 marks]
url_42 = "https://hash-browns.cs.uwaterloo.ca/api/signed/send"

# Sign a message with the signing key
signed = signing_key.sign(b"Attack at Dawn", encoder=Base64Encoder)

data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie", "message": signed
        }

# sending post request and saving response as response object
r = requests.post(url=url_42, data=data)


#Question 5 part 1: verify a public key [2 marks]

url_51 = "https://hash-browns.cs.uwaterloo.ca/api/pke/get-key"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "user": "Nessie"
        }

# sending post request and saving response as response object
r = requests.post(url=url_51, data=data)
public_key = r.json()['public_key']
public_key = base64.b64decode(public_key)
fingerprint = blake2b(data=public_key)
print("The hashed fingerprint received from Nessie in part5:" ,fingerprint)
#6f7d745861af7089ca3c6554c3f80f94bfb2e7eea14f61632cb88988425f02b4

#Question 5 part 2: send a message [2 marks]
sk = PrivateKey.generate()
pk = sk.public_key

pk = pk.__bytes__()
pk = base64.b64encode(pk)

url_52 = "https://hash-browns.cs.uwaterloo.ca/api/pke/set-key"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": pk
        }

# sending post request and saving response as response object
r = requests.post(url=url_52, data=data)

box = Box(sk, nacl.public.PublicKey(public_key))

plaintext = b"wow"
nonce = nacl.utils.random(Box.NONCE_SIZE)
encrypted = box.encrypt(plaintext,nonce)

msg = nonce+encrypted.ciphertext
msg = base64.b64encode(msg)
url_52 = "https://hash-browns.cs.uwaterloo.ca/api/pke/send"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie", "message": msg
        }

# sending post request and saving response as response object
r = requests.post(url=url_52, data=data)

#Question 5 part 3: receive a message [1 mark]
url_53 = "https://hash-browns.cs.uwaterloo.ca/api/pke/inbox"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": pk
        }

# sending post request and saving response as response object
r = requests.post(url=url_53, data=data)
message = r.json()[0]["message"]
message = base64.b64decode(message)
message = box.decrypt(message)
print("The message received from Nessie in q5 part3:", message)


#Question 6 part 1: send a message [3 marks]
govt_pk = "lW4BGqTX4BFpGYz7AxL4Jzh2Xay1Nkvc8jMdOoy8TBY="
govt_pk = base64.b64decode(govt_pk)

sk = PrivateKey.generate()
pk = sk.public_key

pk = pk.__bytes__()
pk = base64.b64encode(pk)


url_61 = "https://hash-browns.cs.uwaterloo.ca/api/surveil/set-key"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": pk
        }

# upload public key
r = requests.post(url=url_61, data=data)

url_61 = "https://hash-browns.cs.uwaterloo.ca/api/surveil/get-key"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "user": "Nessie"
        }

# download Nessie's public key
r = requests.post(url=url_61, data=data)
public_key = r.json()['public_key']
public_key = base64.b64decode(public_key)
public_key = nacl.public.PublicKey(public_key)
#print(public_key)

# 1. Generate a random key, called the message key, for “secret box” encryption.
message_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
# 2. Encrypt the plaintext with the message key using the same technique as question 2. The
# resulting ciphertext is called the message ciphertext. The nonce for this ciphertext is called
# the message nonce
plaintext = b"q6"
secretbox = nacl.secret.SecretBox(message_key)
message_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
message_ciphertext = secretbox.encrypt(plaintext, message_nonce).ciphertext

#3. Encrypt the message key with Nessie’s public encryption key and your secret key using the
#same technique as question 5. The resulting ciphertext is called the recipient ciphertext, and its
# is called the recipient nonce.
part3_box = Box(sk, public_key)
recipient_nonce = nacl.utils.random(Box.NONCE_SIZE)
recipent_ciphertext = part3_box.encrypt(message_key,recipient_nonce).ciphertext

#4. Encrypt the message key with the government’s public encryption key and your secret key
#using the same technique as question 5. The resulting ciphertext is called the government
#ciphertext, and its nonce is called the government nonce.
part4_box = Box(sk, nacl.public.PublicKey(govt_pk))
government_nonce = nacl.utils.random(Box.NONCE_SIZE)
government_ciphertext = part4_box.encrypt(message_key,government_nonce).ciphertext

msg = recipient_nonce+recipent_ciphertext+government_nonce+government_ciphertext+message_nonce+message_ciphertext
msg = base64.b64encode(msg)
url_61 = "https://hash-browns.cs.uwaterloo.ca/api/surveil/send"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie", "message": msg
        }
r = requests.post(url=url_61, data=data)
#print(r.text)

#Question 6 part 2: receive a message [1 mark]
url_62 = "https://hash-browns.cs.uwaterloo.ca/api/surveil/inbox"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        }

r = requests.post(url=url_62, data=data)
message = r.json()[0]["message"]
message = message.encode('ascii')
message = base64.b64decode(message)

message_key = part3_box.decrypt(message[:72])

new_box = nacl.secret.SecretBox(message_key)
decrypted = new_box.decrypt(message[144:])
print("The message received from Nessie in part6:",decrypted)


#Question 7 part 1: upload a signed prekey [1 mark]
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key
verify_key_bytes = verify_key.encode(encoder=Base64Encoder)

url_71 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/set-identity-key"

data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": verify_key_bytes
        }
r = requests.post(url=url_71, data=data)
#print(r.text)


#signed prekey
sk = PrivateKey.generate()
pk = sk.public_key
signed = signing_key.sign(pk.__bytes__())
base64_bytes = base64.b64encode(signed)
url_71 = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/set-signed-prekey'
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "public_key": base64_bytes
        }
r = requests.post(url=url_71, data=data)

#Question 7 part 2: send a message [2 marks]

# get identify verification key
url_72 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/get-identity-key"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "user": "Nessie"
        }
r = requests.post(url=url_72, data=data)

base64_message = r.json()['public_key']
nessie_identity_verification_key = base64_message.encode('ascii')

#get signed prekey
url_72 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/get-signed-prekey"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "user": "Nessie"
        }
r = requests.post(url=url_72, data=data)

base64_message = r.json()['public_key']
nessie_pk = base64_message.encode('ascii')
nessie_pk = base64.b64decode(nessie_pk)

#verify key
verify_key = nacl.signing.VerifyKey(nessie_identity_verification_key,encoder=Base64Encoder)
prekey = verify_key.verify((nessie_pk))

nessie_pk = nacl.public.PublicKey(prekey)

#send msg
box = Box(sk,nessie_pk)
url_72 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/send"
message = b"q7"

nonce = nacl.utils.random(Box.NONCE_SIZE)

encrypted = box.encrypt(message,nonce).ciphertext
encrypted = nonce + encrypted
encrypted = base64.b64encode(encrypted)
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        "to": "Nessie",
        "message": encrypted
        }
r = requests.post(url=url_72, data=data)

#Question 7 part 3: receive a message [1 mark]
url_73 = "https://hash-browns.cs.uwaterloo.ca/api/prekey/inbox"
data = {"Accept header": "application/json",
        "Content-Type header": "application/json",
        'api_token': API_TOKEN,
        }
r = requests.post(url=url_73, data=data)

base64_message = r.json()[0]['message']

base64_bytes = base64_message.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
print("The message received from Nessie in part7:",box.decrypt(message_bytes))