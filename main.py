import DES
from bitarray import bitarray

encryptor = DES.Encryptor(bitarray(56, endian='big'))

message = bitarray(64, endian='big')
cryptogram = encryptor.encrypt(message)

decrypted = encryptor.decrypt(cryptogram)

print(message)
print(decrypted)