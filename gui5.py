from binascii import unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.backends import default_backend


choiceToken = "4a4b5869679c8ce2049ee8a33c2217b0"
choiceByte = unhexlify(choiceToken)
value = b'merhaba'
backend = default_backend()
encryptor = Cipher(algorithms.AES(choiceByte), modes.ECB(), backend).encryptor()
padder = padding2.PKCS7(algorithms.AES(choiceByte).block_size).padder()
padded_data = padder.update(value) + padder.finalize()
encrypted_message = encryptor.update(padded_data) + encryptor.finalize()


backend = default_backend()
decryptor = Cipher(algorithms.AES(choiceByte), modes.ECB(), backend).decryptor()
padder = padding2.PKCS7(algorithms.AES(choiceByte).block_size).unpadder()
decrypted_data = decryptor.update(encrypted_message) 
decrypted_payload = padder.update(decrypted_data) + padder.finalize()

print(decrypted_payload)




payload = b'index::::index2::::'

payload2 = payload[0: len(payload)-4]
print(payload2)
                                       

                                        