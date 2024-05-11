from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
import matplotlib.pyplot as plt
import numpy as np
import pyaes, pbkdf2, binascii, os, secrets
import base64
import array
import random 
from math import ceil 
from decimal import *
import mmap   
from Blockchain import *


main = Tk()
main.title("Efficient Local Secret Sharing for Distributed Blockchain Systems")
main.geometry("1300x1200")

global field_size 
field_size = 10**5

global existing_storage
global dsb_storage
global lss_storage

dictKey = {}

def getRandom():
    return random.randrange(11234,998765)        
   
def reconstructSecret(shares): 
      
    # Combines shares using  
    # Lagranges interpolation.  
    # Shares is an array of shares 
    # being combined 
    sums, prod_arr = 0, [] 
      
    for j in range(len(shares)): 
        xj, yj = shares[j][0],shares[j][1] 
        prod = Decimal(1) 
          
        for i in range(len(shares)): 
            xi = shares[i][0] 
            if i != j: prod *= Decimal(Decimal(xi)/(xi-xj)) 
                  
        prod *= yj 
        sums += Decimal(prod) 
    print(Decimal(sums))      
    return int(round(Decimal(sums),0)) 
   
def polynom(x,coeff): 
      
    # Evaluates a polynomial in x  
    # with coeff being the coefficient 
    # list 
    return sum([x**(len(coeff)-i-1) * coeff[i] for i in range(len(coeff))]) 
   
def coeff(t,secret): 
      
    # Randomly generate a coefficient  
    # array for a polynomial with 
    # degree t-1 whose constant = secret''' 
    coeff = [random.randrange(0, field_size) for _ in range(t-1)] 
    coeff.append(secret) 
      
    return coeff 
   
def generateShares(n,m,secret): 
      
    # Split secret using SSS into 
    # n shares with threshold m 
    cfs = coeff(m,secret) 
    shares = [] 
      
    for i in range(1,n+1): 
        r = random.randrange(1, field_size) 
        shares.append([r, polynom(r,cfs)]) 
      
    return shares 
  
  
def getSomeChunk(filename, start, len):
    fobj = open(filename, 'r+b')
    m = mmap.mmap(fobj.fileno(), 0)
    return m[start:start+len]


def getKey():
    password = "s"
    passwordSalt = '7'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encrypt(plaintext,key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(enc,key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted


def traditionalBlockchain():
    global existing_storage
    text.delete('1.0', END)
    data = tf1.get().strip()
    peers = int(tf2.get().strip())
    local = int(tf3.get().strip())
    key = getKey()
    secret = getRandom()
    dictKey[secret] = key
    enc = encrypt(data,key)
    enc = str(base64.b64encode(enc),'utf-8')
    blockchain = Blockchain()
    blockchain.add_new_transaction(enc)
    hash = blockchain.mine()
    b = blockchain.chain[len(blockchain.chain)-1]
    bdata = b.transactions[0]
    data = base64.b64decode(bdata)
    decrypts = decrypt(data,key)
    text.insert(END,'Private Key : '+str(key)+"\n")
    text.insert(END,'Blockchain Storage : '+str(b.transactions)+"\n")
    text.insert(END,'Previous block hash code : '+str(b.previous_hash)+"\n")
    text.insert(END,'Current block hash code : '+str(b.hash)+"\n")
    text.insert(END,'Decrypted Data : '+str(decrypts.decode("utf-8"))+"\n")
    existing_storage = (len(str(b.previous_hash)) + len(b.hash) + len(key) + len(bdata))
    print(str(len(str(b.previous_hash))) +" "+ str(len(b.hash)) +" "+ str(len(key))+" "+ str(len(bdata)))
    existing_storage = local * peers * existing_storage
    existing_storage = existing_storage / 1000
    text.insert(END,'Traditional Blockchain Storage : '+str(existing_storage))
    
def DSBBlockchain():
    global dsb_storage
    text.delete('1.0', END)
    data = tf1.get().strip()
    peers = int(tf2.get().strip())
    local = int(tf3.get().strip())
    key = getKey()
    secret = getRandom()
    dictKey[secret] = key
    enc = encrypt(data,key)
    enc = str(base64.b64encode(enc),'utf-8')
    blockchain = Blockchain()
    blockchain.add_new_transaction(enc)
    hash = blockchain.mine()
    key = getKey()
    enc = encrypt(data,key)
    t,n = 5, 7
    secret = getRandom()
    text.insert(END,'Original Private Key : '+str(secret)+"\n")
    dictKey[secret] = key
    shares = generateShares(n, t, secret)
    text.insert(END,'Shares generated from private key : '+str(shares)+"\n") 
    length = len(shares)
    share1 = ''
    share2 = ''
    num_block = length / 2
    j = 0
    for i in range(len(shares)):
        if j < num_block:
            value = str(shares[i])
            value = value[1:len(value)-1]
            value = value.split(",")
            value[0] = value[0].strip()
            value[1] = value[1].strip()
            share1+=value[0]+","+value[1]+" "
            j = j + 1
        elif j >= num_block:
            value = str(shares[i])
            value = value[1:len(value)-1]
            value = value.split(",")
            value[0] = value[0].strip()
            value[1] = value[1].strip()
            share2+=value[0]+","+value[1]+" "
            j = j + 1
            
    combine_share = []
    first = share1.strip().split(" ")
    second = share2.strip().split(" ")
    for i in range(len(first)):
        arr = first[i].split(",")
        f = int(arr[0])
        s = int(arr[1])
        temp = [f,s]
        combine_share.append(temp)
    for i in range(len(second)):
        arr = second[i].split(",")
        f = int(arr[0])
        s = int(arr[1])
        temp = [f,s]
        combine_share.append(temp)    
    print(combine_share)
    pool = random.sample(combine_share, t)
    original = reconstructSecret(pool)
    text.insert(END,'\nCombining shares from all shares to generate private key : '+str(combine_share)+"\n") 
    text.insert(END,"Reconstructed private key :"+str(original)+"\n")
    key = dictKey.get(original)
    b = blockchain.chain[len(blockchain.chain)-1]
    bdata = b.transactions[0]
    data = base64.b64decode(bdata)
    decrypts = decrypt(data,key)
    text.insert(END,'Previous block hash code : '+str(b.previous_hash)+"\n")
    text.insert(END,'Current block hash code : '+str(b.hash)+"\n")
    text.insert(END,'Blockchain Storage : '+str(b.transactions)+"\n")
    text.insert(END,'Decrypted Data : '+str(decrypts.decode("utf-8"))+"\n")
    dsb_storage = (len(str(b.previous_hash)) + len(b.hash) + len(key))
    print(str(len(str(b.previous_hash))) +" "+ str(len(b.hash)) +" "+ str(len(key)))
    dsb_storage = local * peers * dsb_storage
    dsb_storage = dsb_storage / 1000
    text.insert(END,'DSB Blockchain Storage : '+str(dsb_storage))

    
def LSS():
    global lss_storage
    text.delete('1.0', END)
    data = tf1.get().strip()
    peers = int(tf2.get().strip())
    local = int(tf3.get().strip())
    key = getKey()
    secret = getRandom()#getting random secret key
    dictKey[secret] = key
    enc = encrypt(data,key)#encrypting data
    enc = str(base64.b64encode(enc),'utf-8')
    blockchain = Blockchain()
    blockchain.add_new_transaction(enc) #creating blockchain object and storing encrypted data
    hash = blockchain.mine() #mining the transaction
    t,n = 5, 7
    text.insert(END,'Original Private Key : '+str(secret)+"\n")
    shares = generateShares(n, t, secret) #generating secret
    text.insert(END,'Shares generated from private key : '+str(shares)+"\n") 
    length = len(shares)
    share1 = ''
    share2 = ''
    num_block = length / 2
    j = 0
    for i in range(len(shares)): #distributing shares to all peers in loop
        if j < num_block:
            value = str(shares[i])
            value = value[1:len(value)-1]
            value = value.split(",")
            value[0] = value[0].strip()
            value[1] = value[1].strip()
            share1+=value[0]+","+value[1]+" "
            j = j + 1
        elif j >= num_block:
            value = str(shares[i])
            value = value[1:len(value)-1]
            value = value.split(",")
            value[0] = value[0].strip()
            value[1] = value[1].strip()
            share2+=value[0]+","+value[1]+" "
            j = j + 1
            
    combine_share = []
    first = share1.strip().split(" ")
    second = share2.strip().split(" ")
    for i in range(len(first)):
        arr = first[i].split(",")
        f = int(arr[0])
        s = int(arr[1])
        temp = [f,s]
        combine_share.append(temp) #gathering or collecting all shares
    for i in range(len(second)):
        arr = second[i].split(",")
        f = int(arr[0])
        s = int(arr[1])
        temp = [f,s]
        combine_share.append(temp) #storing all collected shares in arrat   
    print(combine_share)
    pool = random.sample(combine_share, t)#combining sll shares
    original = reconstructSecret(pool) #reconstructing original secret
    text.insert(END,'\nCombining shares from all shares to generate private key : '+str(combine_share)+"\n") 
    text.insert(END,"Reconstructed private key :"+str(original)+"\n")
    key = dictKey.get(original) #getting key by giving original share
    b = blockchain.chain[len(blockchain.chain)-1]
    bdata = b.transactions[0]
    data = base64.b64decode(bdata)
    decrypts = decrypt(data,key)#decrypting data using private key recover from all shares
    text.insert(END,'Previous block hash code : '+str(b.previous_hash)+"\n")
    text.insert(END,'Current block hash code : '+str(b.hash)+"\n")
    text.insert(END,'Blockchain Storage : '+str(b.transactions)+"\n")
    text.insert(END,'Decrypted Data : '+str(decrypts.decode("utf-8"))+"\n")
    global_storage = (len(str(b.previous_hash)) + len(b.hash)) #calculating storage cost
    local_storage = len(key)
    lss_storage = (global_storage * peers) + (local_storage * local)
    lss_storage = lss_storage / 1000
    text.insert(END,'DSB with LSS Blockchain Storage : '+str(lss_storage))
    

def graph():
    height = [existing_storage,dsb_storage,lss_storage]
    bars = ('Traditional Blockchain Storage','DSB Storage','DSB with LSS Storage')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()
    
font = ('times', 15, 'bold')
title = Label(main, text='Efficient Local Secret Sharing for Distributed Blockchain Systems')
title.config(bg='white', fg='olive drab')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')
ff = ('times', 12, 'bold')

l1 = Label(main, text='Enter Data : ')
l1.config(font=font1)
l1.place(x=50,y=100)

tf1 = Entry(main,width=40)
tf1.config(font=font1)
tf1.place(x=230,y=100)

l2 = Label(main, text='Num Global Peer : ')
l2.config(font=font1)
l2.place(x=50,y=150)

tf2 = Entry(main,width=40)
tf2.config(font=font1)
tf2.place(x=230,y=150)

l3 = Label(main, text='Num Local Peer : ')
l3.config(font=font1)
l3.place(x=50,y=200)

tf3 = Entry(main,width=40)
tf3.config(font=font1)
tf3.place(x=230,y=200)

traditionalButton = Button(main, text="Run Traditional Blockchain", command=traditionalBlockchain)
traditionalButton.place(x=20,y=250)
traditionalButton.config(font=ff)

dsbButton = Button(main, text="Run Distributed Storage Blockchain (DSB)", command=DSBBlockchain)
dsbButton.place(x=270,y=250)
dsbButton.config(font=ff)

lssButton = Button(main, text="Run Distributed Storage Blockchain with LSS", command=LSS)
lssButton.place(x=610,y=250)
lssButton.config(font=ff)

graphButton = Button(main, text="Storage Comparison Graph", command=graph)
graphButton.place(x=980,y=250)
graphButton.config(font=ff)

font1 = ('times', 13, 'bold')
text=Text(main,height=15,width=100)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=300)
text.config(font=font1)

main.config(bg='lightblue')
main.mainloop()
