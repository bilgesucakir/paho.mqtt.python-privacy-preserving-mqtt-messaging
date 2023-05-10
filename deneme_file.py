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


 
def polynomial(x,a,b,c,d):
    y = a *(x*x*x) + b*(x*x) + c *(x) + d
    y = y % 9000
    y += 1000 
    print (y)
 

sample3 = cryptogen.randrange(1000, 9999)
print(sample3)



def hash_vj4(password: str, salt: str):
  dk = hashlib.pbkdf2_hmac('sha512', password.encode(), salt.encode(), 100000)
  print(dk)
  return dk

dk1 =hash_vj4(str(sample), str(sample3) )

dk2 = hash_vj4(str(sample), str(sample3) )

print(len(dk1.hex()))

dk3 =hash_vj4(dk1.hex(), str(sample3) )

dk4 = hash_vj4(dk2.hex(), str(sample3) )
print(dk3.hex())

dk5 =hash_vj4(dk3.hex(), str(sample3) )

dk6 = hash_vj4(dk4.hex(), str(sample3) )
print(dk5.hex())
dk7 =hash_vj4(dk5.hex(), str(sample3) )

dk8 = hash_vj4(dk6.hex(), str(sample3) )
print(dk8.hex())


# write a function that generates the same number between 100 and 999  on both sides of the communication

  

#write a function to input:3987 and output will:3,9,8,7
