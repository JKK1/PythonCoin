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
import sqlite3
import hashlib
import pickle
import os
import datetime
from time import time
from flask import Flask,redirect, flash
from flask import render_template
from flask import send_file
from io import BytesIO
import pickle
from flask import request
import json
from time import sleep
import smtplib
import string
from datetime import timedelta
from flask import Flask, session, redirect, url_for, escape, request
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
import hmac
import os
import time
import struct
import json
from werkzeug import secure_filename
from flask import jsonify
import math
import requests as req
from email.utils import parseaddr
from functools import wraps
import uuid
import traceback
import bcrypt
import sys


socket.setdefaulttimeout(10)

class Wallet(object):
    def __init__(self,rootpeer, keyfolder="keys"):
        self.rootpeer=str(rootpeer)
        self.keyfolder=keyfolder
        loaded,private,public=self.loadkeys()
        if loaded:
            self.keypair=(private,public)
            self.addresses=self.sendgetaddresses()
        else:
            print("could not load keys, generate new ones?")
            if input("Y/N: ").lower()=="y":
                private,public=self.newkeys()
                self.keypair=(private,public)
                self.savekeys()
            self.addresses=[]
        
    def loadkeys(self):
        try:
            priv=self.loadPrivate(open(os.path.join(self.keyfolder,"priv.k"),"rb").read())
            pub=priv.public_key()
            print("correct")
            return True,priv,pub
        except Exception as e:
            if str(e)=="Bad decrypt. Incorrect password?":
                print( str(e))
            return False,"",""

    def savekeys(self, name="priv.k"):
        private=self.keypair[0]
        towrite=private.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.TraditionalOpenSSL,
                                           encryption_algorithm=serialization.BestAvailableEncryption(input("password to encrypt the keys: ").encode()))
        open(os.path.join(self.keyfolder,name),"wb").write(towrite)
        
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

    def sendgetaddresses(self):
        public=self.keypair[1]
        sock=socket.socket()
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="getaddresses"
        message["data"]=self.getpub()
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

    def sendgettransactions(self):
        public=self.keypair[1]
        sock=socket.socket()
        server_address = (self.rootpeer, 7632)
        sock.connect(server_address)
        message={}
        message["method"]="gettransactions"
        message["data"]=self.addresses[0]
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

    def getbalances(self):
        ret=[0.0,0.0,0.0]
        for address in self.addresses:
            res=self.sendgetbalance(address)
            for i in range(len(ret)):
                ret[i]+=res[i]
        return ret

    def gettransactions(self):
        return self.sendgettransactions()
        

    
    
wallet=""
print("connected")
host="localhost"

app = Flask(__name__)
app.debug = True
app.secret_key = "hi"
app.config['LOGGER_HANDLER_POLICY']="never"


def get_decorator():

    def decorator(func):

        def new_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except:
                global wallet
                wallet=Wallet("localhost")
                return redirect("index")

        return new_func

    return decorator

f = get_decorator()



@app.route('/index', methods=['GET'])
@app.route('/dashboard', methods=['GET'])
@app.route('/', methods=['GET'])
@f
def dashboard_get():
    return render_template("index.html", balances=wallet.getbalances(), transactions=wallet.gettransactions()[::-1])
    


@app.route('/send', methods=['GET'])
def send_get():
    try:
        return render_template("send.html", balances=wallet.getbalances(), transactions=wallet.gettransactions()[::-1])
    except:
        return redirect("index")

@app.route('/send', methods=['POST'])
def send_post():
    to=request.form['address']
    from1=wallet.addresses[0]
    amount=float(request.form['amount'])
    fee=float(request.form['fee'])
    wallet.sendnewtransaction(from1,to,amount,fee,random.randint(1,1000000000001))
    return redirect("send")

@app.route('/signatures', methods=['GET'])
def signatures_get():
    try:
        return render_template("signatures.html", balances=wallet.getbalances(),signatures=wallet.sendgetfiles(wallet.addresses[0]))
    except:
        return redirect("index")

@app.route('/signatures', methods=['POST'])
def signatures_post():
    
    method=request.form['method']
    if method=="send":
        file = request.files['address']
        sig=hashlib.sha512(file.read()).digest()
        address=wallet.addresses[0]
        fee=float(request.form['fee'])
        wallet.sendnewfile(sig,fee,address)
        return redirect("signatures")
    else:
        file = request.files['file']
        sig=hashlib.sha512(file.read()).digest()
        files=wallet.sendgetfiles(wallet.addresses[0])
        for file in files:
            if file[0]==sig:
                return str(True)
        return str(False)


@app.route('/settings', methods=['GET'])
def settings_get():
    try:
        action=request.args.get('action')
        if action not in ["keycopy","passchange"]:
            return render_template("settings.html", balances=wallet.getbalances(),rootnode=str(wallet.rootpeer))
        else:
            if action=="keycopy":
                wallet.savekeys(name="copied_priv.k")
            if action=="passchange":
                wallet.savekeys()
            return redirect("settings")
    except Exception as e:
        return redirect("index")
            

@app.route('/settings', methods=['POST'])
def settings_post():
    address=request.form.get('address')
    wallet.rootpeer=address
    return redirect("settings")



if __name__ == '__main__':
    app.run(host=host, port=4379)

print("end")
