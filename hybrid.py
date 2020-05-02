from encryptionAlgorithm import *
import sys

def hybrid(symmetric, asymmetric, plaintext):

	# Encryption
	plaintext = plaintext.encode("utf-8")
	
	if 'AES' in symmetric:
		mode = symmetric.split("-")[1]
		if mode == 'CBC':
			pad_length = 16 - len(plaintext) % 16
			plaintext += bytes([pad_length])*pad_length
		key, iv, ciphertext = AESEncrypt(plaintext, 128, mode)


	if 'TripleDES' in symmetric:
		mode = symmetric.split("-")[1]
		ciphertext, key, iv = tripleDesEncrypt(plaintext,24,mode)
	
	# Formatting data for front-end
	a_key = 'key: ' + key + '\n' + 'Initialization vector(IV): ' + iv
	encrypted_text = ciphertext

	if asymmetric == 'OEAP+RSA':
		encrypted_key, private_key, public_key = RSAEncrypt(key+' '+iv)
		encrypted_a_key = encrypted_key.decode("utf-8")


	if asymmetric == 'El-Gamal':
		encrypted_key, key = ElgamalEncrypt(key+' '+iv)
		u = encrypted_key[0]
		u = u.to_bytes((u.bit_length() + 7) // 8, byteorder=sys.byteorder)
		v = encrypted_key[1]
		v = v.to_bytes((v.bit_length() + 7) // 8, byteorder=sys.byteorder)
		u = base64.b64encode(u).decode("utf-8")
		v = base64.b64encode(v).decode("utf-8")

		encrypted_a_key = "u: " + u + '\n' + 'v: ' + v
		p = int(key.p)
		p = p.to_bytes((p.bit_length() + 7) // 8, byteorder=sys.byteorder)
		p = base64.b64encode(p).decode("utf-8")

		g = int(key.g)
		g = g.to_bytes((g.bit_length() + 7) // 8, byteorder=sys.byteorder)
		g = base64.b64encode(g).decode("utf-8")		

		common = 'Modulus p: ' + p + '\n' + 'Generator g: ' + g + '\n'

		x = int(key.x)
		x = x.to_bytes((x.bit_length() + 7) // 8, byteorder=sys.byteorder)
		x = base64.b64encode(x).decode("utf-8")

		y = int(key.y)
		y = y.to_bytes((y.bit_length() + 7) // 8, byteorder=sys.byteorder)
		y = base64.b64encode(y).decode("utf-8")

		private_key = common + 'Private key, x: ' + x
		public_key = common + 'Public key, y: ' + y

	#else ECC

	#Decryption

	if asymmetric == 'OEAP+RSA':
		decrypted_key = RSADecrypt(encrypted_key, private_key)

	if asymmetric == 'El-Gamal':
		decrypted_key = ElGamalDecrypt(encrypted_key, key)

	#else ECC

	key, iv = decrypted_key.split(" ")
	mode = symmetric.split("-")[1]
	key = base64.b64decode(key)
	iv = base64.b64decode(iv)
	ciphertext = base64.b64decode(ciphertext)

	if 'AES' in symmetric:
		decrypted_text = AESDecrypt(ciphertext, key, iv, mode)
		if mode == 'CBC':
			decrypted_text = decrypted_text[:-decrypted_text[-1]]
		decrypted_text = decrypted_text.decode("utf-8")

	if 'TripleDES' in symmetric:
		decrypted_text = tripleDESDecrypt(ciphertext, key, iv, mode)

	return a_key, encrypted_a_key, encrypted_text, private_key, public_key, decrypted_key, decrypted_text

'''

o = hybrid("TripleDES-CBC","OEAP+RSA","message")

for line in o:
	print(type(line))

'''

