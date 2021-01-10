from Crypto.Cipher import AES
import quantumrandom
import hmac
import hashlib
import pyscrypt

HMAC_KEY = "738525cf1f8acd06beb4cf6cd816d1dc"


class AuthenticationError(Exception):
    pass


def gen_key(password):
    """Derives a key from input string using SCrypt and returns it hex encoded."""
    hashed = pyscrypt.hash(
        password=password,
        salt="2df2e24c76d4d7b37e7ffcdf787e426b",
        N=16384,
        r=8,
        p=1,
        dkLen=16)

    return hashed.encode('hex')


def encrypt(plaintext, password):
    """Takes plaintext input and returns hex encoded ciphertext
    with hex encoded HMAC-SHA-512 hash appended."""

    key = gen_key(password)
    iv = quantumrandom.binary()[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    data = iv.encode("hex") + cipher.encrypt(plaintext).encode("hex")
    sig = hmac.new(HMAC_KEY, data, hashlib.sha512).digest().encode("hex")

    ciphertext = data + sig

    return ciphertext


def decrypt(ciphertext, password):
    """Takes ciphertext and password input, splits it into MAC hash and message
    data, verifies the hash and returns message plaintext if successful."""

    sig = ciphertext[-128:]
    data = ciphertext[:-128]

    if hmac.new(HMAC_KEY, data, hashlib.sha512).digest().encode("hex") != sig:
        raise AuthenticationError("Message Authentication failed!")

    iv = data[:32].decode("hex")
    message = data[32:].decode("hex")
    key = gen_key(password)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return cipher.decrypt(message)


SHARED_SECRET = "correct horse battery staple"
plaintext = "If You're Typing the Letters A-E-S Into Your Code You're Doing It Wrong"
ciphertext = encrypt(plaintext, SHARED_SECRET)

print "Ciphertext:", ciphertext

print "Decrypted:", decrypt(ciphertext, SHARED_SECRET)
