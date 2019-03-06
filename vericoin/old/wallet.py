from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import base58
import pickle
import requests
import codecs

def newkeys():
    private=rsa.generate_private_key(public_exponent=65537,key_size=512, backend=default_backend())
    public=private.public_key()
    return private,public
    
def sign(message, private):
    sig=private.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    return sig



def getpub(public):
    pem=public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem


def newaccount(address,public,private):
    data=[getpub(public),address,sign(getpub(public)+":".encode()+address.encode(),private)]
    data=pickle.loads(pickle.dumps(data))
    print(data)
    print(pickle.dumps(data))
##    r=requests.post("http://localhost:7652/newaccount", data={"data":data})
##    return r.text
    
