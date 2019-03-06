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
import socket
import time
import random
import os
socket.setdefaulttimeout(10)

class wallet(object):
    def __init__(self,rootpeer, keyfolder="keys"):
        self.rootpeer=str(rootpeer)
        self.keyfolder=keyfolder
        loaded,private,public=self.loadkeys()
        if loaded:
            self.keypair=(private,public)
        else:
            print("could not load keys, generate new ones?")
            if input("Y/N: ").lower()=="y":
                private,public=self.newkeys()
                self.keypair=(private,public)
                self.savekeys()
        
    def loadkeys(self):
        try:
            priv=self.loadPrivate(open(os.path.join(self.keyfolder,"priv.k"),"rb").read())
            pub=priv.public_key()
            return True,priv,pub
        except Exception as e:
            if str(e)=="Bad decrypt. Incorrect password?":
                raise str(e)
            return False,"",""

    def savekeys(self):
        private=self.keypair[0]
        towrite=private.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.TraditionalOpenSSL,
                                           encryption_algorithm=serialization.BestAvailableEncryption(input("password to encrypt the keys: ").encode()))
        open(os.path.join(self.keyfolder,"priv.k"),"wb").write(towrite)
        
    def loadPublic(self, pem):
        public = serialization.load_pem_public_key(
        pem,
        backend=default_backend())
        return public
    
    def loadPrivate(self, pem):
        private = serialization.load_pem_private_key(
        pem,
        password=input("private key password: ").encode(),
        backend=default_backend())
        return private
    
    def newkeys(self):
        private=rsa.generate_private_key(public_exponent=65537,key_size=512, backend=default_backend())
        public=private.public_key()
        keypair=(private,public)
        return private,public
    
    def sign(self, message):
        private=self.keypair[0]
        sig=private.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return sig

    def getpub(self):
        public=self.keypair[1]
        pem=public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem

    def newaccount(self, address):
        private=self.keypair[0]
        public=self.keypair[1]
        data=[self.getpub(),address,self.sign(self.getpub()+":".encode()+address.encode())]
        return data

    def newfile(self, hash,fee,address):
        private=self.keypair[0]
        data=[address,hash,fee,self.sign(address.encode()+":".encode()+hash+":".encode()+str(fee).encode())]
        return data

    def newtransaction(self, address1,address2,amount,fee,nonce):
        private=self.keypair[0]
        data=[address1,address2,amount,fee,nonce,self.sign(address1.encode()+":".encode()+address2.encode()+":".encode()+str(amount).encode()+":".encode()+str(fee).encode()+":".encode()+str(nonce).encode())]
        return data

    def sendnewaccount(self, address):
        private=self.keypair[0]
        public=self.keypair[1]
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="newaccount"
        message["data"]=self.newaccount(address)
        sock.sendall(pickle.dumps(message))
        sock.close()

    def sendnewpeer(self):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="addpeer"
        message["data"]=[]
        sock.sendall(pickle.dumps(message))
        data=b""
        while True:
            new=sock.recv(2**20)
            data += new
            try:
                data = pickle.loads(data)
                break
            except:
                ""
        sock.close()
        return data
    


    def sendnewfile(self,hash,fee,address):
        private=self.keypair[0]
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="newfile"
        message["data"]=self.newfile(hash,fee,address)
        sock.sendall(pickle.dumps(message))
        sock.close()

    def sendnewtransaction(self,address1,address2,amount,fee,nonce):
        private=self.keypair[0]
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="newtransaction"
        message["data"]=self.newtransaction(address1,address2,amount,fee,nonce)
        sock.sendall(pickle.dumps(message))
        sock.close()

    def sendgetinfo(self):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getinfo"
        message["data"]=[]
        sock.sendall(pickle.dumps(message))
        data=b""
        while True:
            new=sock.recv(2**20)
            data += new
            try:
                data = pickle.loads(data)
                break
            except:
                ""
        sock.close()
        return data

    def sendgetblock(self, block):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getblock"
        message["data"]=block-1
        sock.sendall(pickle.dumps(message))
        data=b""
        while True:
            new=sock.recv(16)
            data += new
            try:
                data = pickle.loads(data)
                break
            except:
                ""
        sock.close()
        return data

    def sendnewblock(self,block):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="newblock"
        message["data"]=block
        sock.sendall(pickle.dumps(message))
        sock.close()

        

    def constructblock(self,info,miner,version=1):
        number=info[5]+1
        stime=int(time.time())
        accounts=info[2]
        random.shuffle(accounts)
        transactions=info[0]
        random.shuffle(transactions)
        files=info[1]
        random.shuffle(files)
        lasthash=info[4]
        block={"block":[number,miner,lasthash,stime,version,info[3]],
               "accounts":accounts,
               "transactions":transactions,
               "files":files}
        return block

    def hashblock(self,block):
        tohash=str(block).encode()
        result=hashlib.sha512(tohash).hexdigest()
        return result

    def sendgetbalance(self, address):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getbalance"
        message["data"]=address
        sock.sendall(pickle.dumps(message))
        data=b""
        while True:
            new=sock.recv(16)
            data += new
            try:
                data = pickle.loads(data)
                break
            except:
                ""
        sock.close()
        return data

    def sendgetfiles(self, address):
        sock=socket.socket()
        ""
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getfiles"
        message["data"]=address
        sock.sendall(pickle.dumps(message))
        data=b""
        while True:
            new=sock.recv(16)
            data += new
            try:
                data = pickle.loads(data)
                break
            except:
                ""
        sock.close()
        return data
    
    def mine(self,miner):
        while True:
            info=self.sendgetinfo()
            for _ in range(10000):
                block=self.constructblock(info,miner)
                result=self.hashblock(block)
                diff=info[3]
                time.sleep(1)
                if int(result,16)<(2**512)//diff:
                    print("newblock")
                    self.sendnewblock(block)
                    info=self.sendgetinfo()
        
