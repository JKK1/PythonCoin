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

class Wallet(object):
    def __init__(self,rootpeer, keyfolder="keys"):
        self.rootpeer=str(rootpeer)
        self.miner=input("mine to: ")
        self.mine(self.miner)


    


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
        
wallet=Wallet(input("rootpeer: "))
