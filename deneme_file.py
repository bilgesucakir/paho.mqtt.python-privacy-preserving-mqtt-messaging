from random import SystemRandom
import hashlib
from django.utils.encoding import force_bytes, force_str
import codecs
import numpy as np


cryptogen = SystemRandom()
sample = cryptogen.randrange(1000000000, 9999999999)
#print(sample)
sample2 = cryptogen.randrange(100, 999)
#print(sample2)


 
def polynomial(x):
    y = 4 *(x*x*x) + 3*(x*x) + 2 *(x) + 10
    y = y % 9000
    y += 1000 
    print (y)
 

sample3 = cryptogen.randrange(1000, 9999)
print(sample3)

polynomial2(9999)


"""
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

"""
  


