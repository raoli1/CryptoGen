import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Cipher import DES3
import base64
import sys
import codecs

# Asymmetric

# RSA
def RSAEncrypt(message, key_size = 2048):
    '''
    :param message: str
    :param key_size: 2048 or 4096
    :return: base64 encoded ciphertext, private key, public key
    '''
    private_key = rsa.generate_private_key(public_exponent = 65537,
                                           key_size = key_size,
                                           backend = default_backend())
    public_key = private_key.public_key()
    message_byte = bytes(message, encoding = 'utf-8')
    cipher_text = public_key.encrypt(message_byte,
                                     padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                                  algorithm = hashes.SHA256(),
                                                  label = None)
                                     )

    # serialization
    pem_priv = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    pem_pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(cipher_text), pem_priv.decode("utf-8"), pem_pub.decode("utf-8")

def RSADecrypt(cipher_text, pem):
    '''
    :param cipher_text: base64 encoded ciphertext
    :param pem: byte object
    :return: byte object
    '''
    cipher_text = base64.b64decode(cipher_text)
    pem = pem.encode("utf-8")
    private_key = serialization.load_pem_private_key(pem, None, backend=default_backend())
    plain_text = private_key.decrypt(cipher_text,
                                     padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                                  algorithm = hashes.SHA256(),
                                                  label = None)
                                     )
    return plain_text.decode("utf-8")

def ElgamalEncrypt(message):
    key = ElGamal.generate(1024, Random.new().read)
    while 1:
        k = random.StrongRandom().randint(1, int(key.p - 1))
        if GCD(k, int(key.p - 1)) == 1: break

    m = int(message.encode('utf-8').hex(),16)
    cipher_text = key._encrypt(m,k)
    return cipher_text, key


def ElGamalDecrypt(cipher_text,key):
    plain_text = key._decrypt(cipher_text)
    plain_text = hex(plain_text)[2:]
    plain_text = bytes.fromhex(plain_text).decode("utf-8")
    return plain_text
# Symmetric encryption - AES
def AESEncrypt(message, key_size, mode):
    '''
    :param message:  byte object
    :param key_size:  (int) 128, 192 or 256
    :param mode:  (str) CBC, CTR, OFB, CFB
    :return: byte obejct
    '''

    key = os.urandom(int(key_size//8))
    iv = os.urandom(16)

    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend())
    if mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend = default_backend())
    if mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())

    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(key).decode("utf-8"), base64.b64encode(iv).decode("utf-8"), base64.b64encode(ct).decode("utf-8")

def AESDecrypt(cipher_text, key, iv, mode):
    '''
    :param cipher_text: byte object
    :param key: byte object
    :param iv: byte object
    :param mode: (str) CBC, CTR, OFB, CFB
    :return: byte object
    '''
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend())
    if mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend = default_backend())
    if mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()


# Symmetric encryption - 3DES

def tripleDesEncrypt(message,key_size,mode):
    '''
    :param message: byte object
    :param key_size: key size (must be either 16 or 24 bytes long)
    :param mode: OFB,CBC,CFB
    :return: byte object
    '''
    key = os.urandom(int(key_size))
    iv = Random.new().read(DES3.block_size)

    # plaintext length (in bytes) must be a multiple of block_size.
    pad_length = 8 - len(message) % 8
    message += bytes([pad_length])*pad_length
    
    if mode == 'OFB':
        cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)
    if mode == 'CBC':
        cipher_encrypt = DES3.new(key,DES3.MODE_CBC,iv)
    if mode == 'CFB':
        cipher_encrypt = DES3.new(key,DES3.MODE_CFB,iv)
    if mode == 'CTR':
        cipher_encrypt = DES3.new(key,DES3.MODE_CTR, counter = lambda :iv)

    cipher_text = cipher_encrypt.encrypt(message)

    return base64.b64encode(cipher_text).decode("utf-8"), base64.b64encode(key).decode("utf-8"), base64.b64encode(iv).decode("utf-8")

# message = b'hihihi'
# print(tripleDesEncrypt(message,16,'CFB'))

def tripleDESDecrypt(cipher_text, key, iv, mode):
    '''
    :param cipher_text: byte object
    :param key: byte object
    :param iv: byte object
    :param mode: OFB, CBC, CFB
    :return: byte object
    '''
    if mode == 'OFB':
        cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)
    if mode == 'CBC':
        cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
    if mode == 'CFB':
        cipher_decrypt = DES3.new(key, DES3.MODE_CFB,iv)
    if mode =='CTR':
        cipher_decrypt = DES3.new(key,DES3.MODE_CTR,counter = lambda :iv)

    plain_text = cipher_decrypt.decrypt(cipher_text)
    plain_text = plain_text[:-plain_text[-1]]
    return plain_text.decode("utf-8")

# key exchange
def ECDHServer(peer_public_key):
    '''

    :param peer_public_key: ellipticalPublicKey Object
    :return: byte objects
    '''
    server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    shared_key = server_private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',
                       backend=default_backend()).derive(shared_key)
    return derived_key



def ECDHPeer(server_public_key):
    '''

    :param server_public_key: ellipticalPublicKey Object
    :return: byte type
    '''
    peer_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    shared_key = peer_private_key.exchange(ec.ECDH(), server_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',
                       backend=default_backend()
).derive(shared_key)
    return derived_key






