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
import json
import codecs
import socket
import time
import random

class VeriCoin(object):
    ""
    def __init__(self, rootpeer,myip, folder="blocks", first=False):
        """Start node"""
             
        
        try:
            peerdata=self.sendgetinfo(rootpeer)
            self.newtransactions=peerdata[0]
            self.newfiles=peerdata[1]
            self.newaccounts=peerdata[2]
            self.peers=[]
            self.stablishpeers(rootpeer)
        except:
            print("no peers, continue (Y/N)")
            if input().lower()!="y":
                raise "error"
            else:
                self.newfiles=[]
                self.newtransactions=[]
                self.newaccounts=[]
                self.peers=[]

        self.myip=myip
        self.folder=folder
        self.refresh()
        self.rootpeer=rootpeer
        self.signatures=self.getpastsignatures()
        self.checksync()

    def checksync(self):
        peers=self.peers
        
        for peer in peers:
            try:
                if self.sendgetinfo(peer)[5]>self.blockcount:
                    print("syncing")
                    self.resync(peer)
                    self.checksync()
            except:
                print("lost peer: "+str(peer))
                self.peers.remove(peer)
                try:
                    self.seekpeer()
                except:
                    ""
        try:
            self.seekroot()
        except:
            ""
        
    def seekroot(self):
        if len(self.peers)==0:
            self.stablishpeers(self.rootpeer)

    def seekpeer(self):
        if len(self.peers)>0:
            self.stablishpeers(random.sample(self.peers,1)[0])
        else:
            self.stablishpeers(self.rootpeer)
        if len(self.peers)==0:
            print("nopeers, restart with new rootpeer")

        

    def resync(self,peer):
        lastmatch=0
        wrong=False
        oblocks=self.blocks
        try:
            for i in range(self.blockcount,0,-1):
                peerblock=self.getblockfrompeer(peer,i)
                if peerblock==self.blocks[i-1]:
                    lastmatch=i
                    break
            for i in range(lastmatch+1,self.sendgetinfo(peer)[5]+1):
                peerblock=self.getblockfrompeer(peer,i)
                #print(peerblock)
                if i==1:
                    if self.verblock(peerblock,diff=1,first=True, overtime=True):
                        pickle.dump(peerblock,open(os.path.join(self.folder,str(self.formating(self.blockcount+1))+".blk"),"wb"))
                        self.refresh()
                    else:
                        wrong=True
                elif i==2:
                    if self.verblock(peerblock,diff=1, overtime=True):
                        pickle.dump(peerblock,open(os.path.join(self.folder,str(self.formating(self.blockcount+1))+".blk"),"wb"))
                        self.refresh()
                    else:
                        wrong=True
                else:
                    if self.verblock(peerblock,diff=self.difficulty, overtime=True):
                        pickle.dump(peerblock,open(os.path.join(self.folder,str(self.formating(self.blockcount+1))+".blk"),"wb"))
                        self.refresh()
                    else:
                        wrong=True
            
        except:
            wrong=True
        if wrong:
            self.writeblocks(oblocks)

    def writeblocks(self,blocks):
        for i in range(len(blocks)):
            blocks[i]
            pickle.dump(blocks[i],open(os.path.join(self.folder,str(self.formating(i+1))+".blk"),"wb"))

    def testalive(self):
        peers=self.peers
        for peer in peers:
            message={}
            message["method"]="testalive"
            try:
                self.sendrawpeer(peer,message)
            except:
                self.peers.remove(peer)


            
    def getblockfrompeer(self,peer,block):
        sock=socket.socket()
        sock.settimeout(1.7)
        server_address = (peer, 7632)
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

    def peerspread(self,data):
        peers=self.peers
        for peer in peers:
            self.sendrawpeer(peer,data)

    def sendgetinfo(self,peer):
        sock=socket.socket()
        sock.settimeout(1.7)
        server_address = (peer, 7632)
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
    
    def stablishpeers(self, rootpeer):
        peers=self.sendgetpeers(rootpeer)
        errors=0
        for peer in peers:
            if peer!=self.myip:
                if self.sendaddpeer(peer):
                    self.peers.append(peer)
                else:
                    errors+=1
        
        if len(self.peers)!=0 and len(self.peers)<1:
            self.stablishpeers(self.peers[0])
        if len(self.peers)==0:
            raise "No available peers found from this rootpeer"
    
    def sendaddpeer(self,peer):
        sock=socket.socket()
        server_address = (peer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="addpeer"
        message["data"]=[]
        sock.sendall(pickle.dumps(message))
        data=b""
        anwser=sock.recv(2**20)
        sock.close()
        return anwser

    def sendrawpeer(self,peer,message):
        sock=socket.socket()
        sock.settimeout(1.7)
        server_address = (peer, 7632)
        sock.connect(server_address)
        sock.sendall(pickle.dumps(message))
        try:
            data=sock.recv(2**20)
        except:
            data=b""
        sock.close()
        return data
    
    def sendgetpeers(self,peer):
        sock=socket.socket()
        server_address = (peer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getpeers"
        message["data"]=[]
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

    def refresh(self):
        self.blockcount=len(os.listdir(self.folder))
        self.blocks=self.getblocks()
        self.accounts=self.gataccounts()
        self.balances=self.getbalances()
        self.signatures=self.getsignatures()
        try:
            blocks=self.blocks[-2:]
            difference=blocks[1]["block"][3]-blocks[0]["block"][3]
            self.difficulty=self.getlastblockdiff()
            diff=int(self.difficulty*(60/difference))+1
            if diff<1:
                diff=1
            self.difficulty=diff
            print(diff)
        except:
            self.difficulty=-1

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
                        signatures[file[0]].append((file[1],file[2]))
                    else:
                        signatures[file[0]]=[(file[1],file[2])]
        return signatures

    def getpastsignatures(self):
        signatures=[]
        for block in self.blocks:
            files=block["files"]
            for file in files:
                if self.versignature(file):
                    signatures.append(file[2])
                    
            accounts=block["accounts"]
            for account in accounts:
                if self.veraccount(account):
                   signatures.append(account[2])
                   
            transactions=block["transactions"]
            for transaction in transactions:
                if self.vertransaction(transaction):
                   signatures.append(transaction[2])
                   
        return signatures

    def versignature(self, file):
        message=file[0].encode()+":".encode()+file[1]
        public=self.loadPublic(self.getpub(file[0]))
        return self.verify(message,file[2],public)
    
    def vertransaction(self,transaction):
        message=transaction[0]+":"+transaction[1]+":"+str(transaction[2])+":"+str(transaction[3])
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
        return self.newtransactions,self.newfiles,self.newaccounts,self.difficulty,self.lasthash(),self.blockcount

    def lasthash(self):
        return self.hashblock(self.blocks[self.blockcount-1])

    def hashblock(self,block):
        tohash=str(block).encode()
        result=hashlib.sha512(tohash).hexdigest()
        return result

    def verblock(self,block,diff,first=False,overtime=False):
        if not self.blocksanity(block,diff=diff,first=first, overtime=overtime):
            return False
        result=self.hashblock(block)
        if int(result,16)<(2**512)//diff:
            return True
        return False

    def blocksanity(self,block,diff=False,first=False,overtime=False):
        if diff==False:
            diff=self.difficulty
        try:
            int(block["block"][0])
            if block["block"][0]!=self.blockcount+1:
                #print("1")
                return False
            if first:
                if block["block"][2]!="":
                    #print("2")
                    return False
            else:
                if block["block"][2]!=self.lasthash():
                    #print("3")
                    return False
            if not overtime:
                if time.time()+10 < block["block"][3] or block["block"][3] < time.time()-10:
                    #print("4")
                    return False
            if block["block"][4]!=1:
                #print("5")
                return False
            if block["block"][5]!=diff:
                #print("6")
                return False
            if len(block["block"])!=6:
                #print("7")
                return False
            for account in block["accounts"]:
                if not self.veraccount(account):
                    #print("8")
                    return False
                if account[1] in blockchain.accounts:
                    #print("9")
                    return False
            for transaction in block["transactions"]:
                if not self.vertransaction(transaction):
                    #print("10")
                    return False

            for file in block["files"]:
                if not self.versignature(file):
                    return False
            if len(block)!=4:
                return False
        except Exception as e:
            print(e)
            return False
        
        return True

    def getlastblockdiff(self):
        return self.blocks[self.blockcount-1]["block"][5]


    def deletenews(self,block):
        for account in block["accounts"]:
            try:
                self.newaccounts.remove(account)
            except:
                ""
        for transaction in block["transactions"]:
            try:
                self.newtransactions.remove(transaction)
            except:
                ""
        for file in block["files"]:
            try:
                self.newfiles.remove(file)
            except:
                ""
        onewaccounts=self.newaccounts
        onewtransactions=self.newtransactions
        onewfiles=self.newfiles
        self.newaccounts=[]
        self.newtransactions=[]
        self.newfiles=[]
        for account in onewaccounts:
            if account[2] not in blockchain.signatures:
                if blockchain.veraccount(account) and account[1] not in blockchain.accounts:
                    self.newaccounts.append(account)
        for transaction in onewtransactions:
            if blockchain.checkbalance(transaction[0],transaction[2]):
                if transaction[4] not in blockchain.signatures:
                    if blockchain.vertransaction(transaction):
                        self.newtransactions.append(transaction)
        for file in onewfiles:
            if file[2] not in blockchain.signatures:
                if blockchain.versignature(file):
                    self.newfiles.append(file)
                    
                
    def checkbalance(self,address, amount):
        if blockchain.balances[address]>=amount:
            return True
        return False
    
    def formating(self,n):
        num=str(n)
        extra="0"*(20-len(num))
        return extra+num

    def getbalance(self,address):
        return blockchain.balances[address]

    def addpeer(self,peer):
        if peer!=self.myip:
            if peer not in self.peers:
                self.peers.append(peer)
        

timeout=0.4
socket.setdefaulttimeout(1)
sock=socket.socket()
sock.settimeout(timeout)
myip=input("ip address: ")
sock.bind((myip,7632))
sock.listen()
rootpeer=input("rootpeer ip: ")
blockchain=VeriCoin(rootpeer,myip)
print("starting in 10")
time.sleep(10)
blockchain=VeriCoin(rootpeer,myip)

while True:
    print(blockchain.peers)
    blockchain.checksync()
    blockchain.peers=list(set(blockchain.peers))
    for _ in range(int(10//timeout)):
        try:
            connection,clientadddress= sock.accept()
            while True:
                data=b""
                p=0
                while p<10000:
                    new=connection.recv(2**20)
                    data += new
                    try:
                        data = pickle.loads(data)
                        break
                    except:
                        p+=1
                if p==10:
                    break
                if data["method"]=="newblock":
                    #print("newblock in")
                    if blockchain.verblock(data["data"],blockchain.difficulty):
                        print("new")
                        pickle.dump(data["data"],open(os.path.join(blockchain.folder,str(blockchain.formating(blockchain.blockcount+1))+".blk"),"wb"))
                        blockchain.deletenews(data["data"])
                        blockchain.refresh()
                        blockchain.peerspread(data)
                        connection.sendall(b"done")
                    else:
                        connection.sendall(b"no")
                    break

                if data["method"]=="newtransaction":
                    if not blockchain.checkbalance(data["data"][0],data["data"][2]):
                        connection.sendall(b"not enough balance")
                        break
                    if data["data"][4] in blockchain.signatures:
                        connection.sendall(b"repeated signature")
                        break
                    if blockchain.vertransaction(data["data"]):
                        t=True
                        for transaction in blockchain.newtransactions:
                            if transaction[0]==data["data"][0]:
                                connection.sendall(b"no")
                                t=False
                                break
                        if t:
                            blockchain.newtransactions.append(data["data"])
                            blockchain.peerspread(data)
                            connection.sendall(b"done")
                    else:
                        connection.sendall(b"no")
                    break
                
                if data["method"]=="newfile":
                    if data["data"][2] in blockchain.signatures:
                        connection.sendall(b"repeated signature")
                        break
                    if blockchain.versignature(data["data"]) and data["data"] not in blockchain.newfiles:
                        t=True
                        for file in blockchain.newfiles:
                            if file[1]==data["data"][1]:
                                connection.sendall(b"no")
                                t=False
                                break
                        if t:
                            blockchain.newfiles.append(data["data"])
                            blockchain.peerspread(data)
                            connection.sendall(b"done")
                    else:
                        connection.sendall(b"no")
                    break
                
                if data["method"]=="newaccount":
                    if data["data"][2] in blockchain.signatures:
                        connection.sendall(b"repeated")
                        break
                    if blockchain.veraccount(data["data"]) and data["data"][1] not in blockchain.accounts:
                        t=True
                        for account in blockchain.newaccounts:
                            if account[1]==data["data"][1]:
                                t=False
                                break
                        if t:
                            blockchain.newaccounts.append(data["data"])
                            blockchain.peerspread(data)
                            connection.sendall(b"done")
                        else:
                            connection.sendall(b"no")
                            
                    else:
                        
                        connection.sendall(b"no")
                    break
                
                if data["method"]=="getinfo":
                    connection.sendall(pickle.dumps(blockchain.servedata()))
                    break
                
                if data["method"]=="getblock":
                    connection.sendall(pickle.dumps(blockchain.blocks[data["data"]]))
                    break

                if data["method"]=="getbalance":
                    connection.sendall(pickle.dumps(blockchain.getbalance(data["data"])))
                    break
                if data["method"]=="addpeer":
                    if blockchain.addpeer(clientadddress[0]):
                        connection.sendall(b"done")
                    else:
                        connection.sendall(b"no")
                    break
                if data["method"]=="getpeers":
                    connection.sendall(pickle.dumps(blockchain.peers+[myip]))
                    break
                if data["method"]=="testalive":
                    connection.sendall(b"still here")
                    break
                connection.sendall(b"no")
                break
        except Exception as e:
            if str(e)!="timed out":
                raise e
            if "KeyboardInterrupt" in str(e):
                print(e)
                break
    
        
        
