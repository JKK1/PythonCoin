from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import base58
import os
import pickle
from flask import Flask,request
import json
import codecs

app = Flask(__name__)

class VeriCoin(object):
    def __init__(self, peers, folder="blocks", SuperNode=False, first=False):
        """Start wallet"""
        if SuperNode and first:
            self.newtransactions=[]
            self.newfiles=[]
            self.newaccounts=[]
            self.difficulty=1
        else:
            peerdata=getpeerdata(peers)
            self.newtransactions=peerdata[0]
            self.newfiles=peerdata[1]
            self.newaccounts=peerdata[2]
            self.difficulty=peerdata[3]

        self.folder=folder
        self.refresh()
        self.SuperNode=SuperNode
        self.peers=peers
        
        

    def refresh(self):
        self.blockcount=len(os.listdir(self.folder))
        self.blocks=self.getblocks()
        self.accounts=self.gataccounts()
        self.balances=self.getbalances()
        self.signatures=self.getsignatures()

    def getblocks(self):
        r=[]
        blocks=os.listdir(self.folder)
        blocks.sort()
        for i in blocks:
            if i[-4:]==".blk":
                r.append(pickle.load(open(os.path.join(self.folder,i),"rb")))
        return r

    def gataccounts(self):
        accs={}
        for block in self.blocks:
            accounts=block["accounts"]
            for account in accounts:
                if account[1] not in accs:
                    if self.veraccount(account):
                        accs[account[1]]=account[0]
        return accs

    def getbalances(self):
        bals={}
        for block in self.blocks:
            miner=block["block"][1]
            if miner in bals:
                bals[miner]+=8
            else:
                bals[miner]=8
            transactions=block["transactions"]
            for transaction in transactions:
                if self.vertransaction(transaction):
                    bals[transaction[0]]-=float(transaction[2])
                    if transaction[1] in bals:
                        bals[transaction[1]]+=float(transaction[2])
                    else:
                        bals[transaction[1]]=float(transaction[2])
        return bals

    def getsignatures(self):
        signatures={}
        for block in self.blocks:
            files=block["files"]
            for file in files:
                if self.versignature(file):
                    if file[0] in signatures:
                        signatures[file[0]].append(file[1])
                    else:
                        signatures[file[0]]=[file[1]]
        return signatures

    def versignature(self, file):
        message=file[0]+":"+file[1]
        public=self.loadPublic(self.getpub(file[0]))
        return self.verify(message.encode(),file[2],public)
    
    def vertransaction(self,transaction):
        message=transaction[0]+":"+transaction[1]+":"+transaction[2]+":"+str(transaction[3])
        public=self.loadPublic(self.getpub(transaction[0]))
        return self.verify(message.encode(),transaction[4],public)

    def veraccount(self,account):
        message=account[0]+":".encode()+account[1].encode()
        public=self.loadPublic(account[0])
        return self.verify(message,account[2],public)
        
    def getpub(self,address):
        try:
            return self.accounts[address]
        except:
            raise "error"

    def freeaddress(self, address):
        if addres not in self.accounts:
            return True
        return False
    
    def loadPublic(self, pem):
        public = serialization.load_pem_public_key(
        pem,
        backend=default_backend())
        return public
    
    def verify(self, message, sig, public):
        try:
            public.verify(sig,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            return True
        except:
            return False
    def servedata(self):
        return self.newtransactions,self.newfiles,self.newaccounts,self.difficulty

blockchain=VeriCoin([],SuperNode=True,first=True)

@app.route('/api', methods=['GET'])
def api():
    return json.dumps(block.servedata())

@app.route('/newtransaction', methods=['POST'])
def newtransaction():
    data = request.form.get('data')
    blockchain.newtransaction.append(pickle.loads(data))
    return "ok"

@app.route('/newaccount', methods=['POST'])
def newaccount():
    data = request.form.get('data')
    blockchain.newaccounts.append(pickle.loads(codecs.encode(data,encoding="base64")))
    return "ok"

@app.route('/newfile', methods=['POST'])
def newfile():
    data = request.form.get('data')
    blockchain.newfiles.append(pickle.loads(data))
    return "ok"

@app.route('/getblockcount', methods=['GET'])
def getcount():
    return str(blockchain.blockcount)

@app.route('/getblock/<block>', methods=['GET'])
def getblock(block):
    if block>0:
        return json.dumps(blockchain.blocks[int(block)-1])
    return ""

@app.route('/pushblock', methods=['POST'])
def pushblock():
    print(data)
    data = request.form.get('data')
    
    if blockchain.testaccept(pickle.loads(data)):
        return "ok"
    else:
        return "no"



if __name__ == '__main__':
	app.run(host="localhost", port=7652, debug=True)
