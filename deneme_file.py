from random import SystemRandom
cryptogen = SystemRandom()
sample = cryptogen.randrange(1000000000, 9999999999)
print(sample)
