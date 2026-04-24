from aes import AES

# AES testing
aes = AES('LEHUYNHANHKHOI24')
print(aes.encrypt('DLK24DHGTVTTPHCM'))
print(aes.decrypt('bb15880b6c2baeea4b3441a7c765ec78'))

aes_128 = AES("Sixteen byte key")
ciphertext = aes_128.encrypt("Sixteen byte txt")
print("AES-128 Encrypted:", ciphertext)
print("AES-128 Decrypted:", aes_128.decrypt(ciphertext))

aes_192 = AES("Twenty-four byte key!!!!")
ciphertext = aes_192.encrypt("Sixteen byte txt")
print("AES-192 Encrypted:", ciphertext)
print("AES-192 Decrypted:", aes_192.decrypt(ciphertext))

aes_256 = AES("This is a 256bit key, 32 chars!!")
ciphertext = aes_256.encrypt("Sixteen byte txt")
print("AES-256 Encrypted:", ciphertext)
print("AES-256 Decrypted:", aes_256.decrypt(ciphertext))
