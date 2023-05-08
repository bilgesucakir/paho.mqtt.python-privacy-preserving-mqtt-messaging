from random import SystemRandom
import hashlib
from django.utils.encoding import force_bytes, force_str
import codecs


cryptogen = SystemRandom()
sample = cryptogen.randrange(1000000000, 9999999999)
print(sample)
sample2 = cryptogen.randrange(100, 999)
print(sample2)

sample3 = cryptogen.randrange(100, 999)
print(sample3)


def hash_vj4(password: str, salt: str):
  dk = hashlib.pbkdf2_hmac('sha512', password.encode(), salt.encode(), 100000)
  print(dk)
  return dk

dk1 =hash_vj4(str(sample), str(sample2) )

dk2 = hash_vj4(str(sample), str(sample2) )

dk3 =hash_vj4(dk1.hex(), str(sample2) )

dk4 = hash_vj4(dk2.hex(), str(sample2) )

dk5 =hash_vj4(dk3.hex(), str(sample2) )

dk6 = hash_vj4(dk4.hex(), str(sample2) )

dk7 =hash_vj4(dk5.hex(), str(sample2) )

dk8 = hash_vj4(dk6.hex(), str(sample2) )


# write a function that generates the same number between 100 and 999  on both sides of the communication

def polynomial():
  


