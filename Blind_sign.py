#!/usr/bin/env python
# coding: utf-8

# In[ ]:



# Cryptomath Module

import random

def gcd(a, b):
    # Returns the GCD of positive integers a and b using the Euclidean Algorithm.
    x, y = a, b
    while y != 0:
        r = x % y
        x = y
        y = r
    return x

def extendedGCD(a,b):
    # Returns integers u, v such that au + bv = gcd(a,b).
    x, y = a, b
    u1, v1 = 1, 0
    u2, v2 = 0, 1
    while y != 0:
        r = x % y
        q = (x - r) // y
        u, v = u1 - q*u2, v1 - q*v2
        x = y
        y = r
        u1, v1 = u2, v2
        u2, v2 = u, v
    return (u1, v1)

def findModInverse(a, m):
    # Returns the inverse of a modulo m, if it exists.
    if gcd(a,m) != 1:
        return None
    u, v = extendedGCD(a,m)
    return u % m

def RabinMiller(n):
    # Applies the probabilistic Rabin-Miller test for primality.
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    d = n - 1
    s = 0
    while(d % 2 == 0):
        s += 1
        d = d // 2
    # At this point n - 1 = 2^s*d with d odd.
    # Try fifty times to prove that n is composite.
    for i in range(50):
        a = random.randint(2, n - 1)
        if gcd(a, n) != 1:
            return False
        b = pow(a, d, n)
        if b == 1 or b == n - 1:
            continue
        isWitness = True
        r = 1
        while(r < s and isWitness):
            b = pow(b, 2, n)
            if b == n - 1:
                isWitness = False
            r += 1
        if isWitness:
            return False
    return True
            

def isPrime(n):
    # Determines whether a positive integer n is composite or probably prime.
    if n < 2:
        return False
    smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                   59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                   127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
                   191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                   257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                   331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
                   401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
                   467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                   563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
                   631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                   709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                   877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
                   967, 971, 977, 983, 991, 997]
    # See if n is a small prime.
    if n in smallPrimes:
        return True
    # See if n is divisible by a small prime.
    for p in smallPrimes:
        if n % p == 0:
            return False
    # Apply Fermat test for compositeness.
    for base in [2,3,5,7,11]:
        if pow(base, n - 1, n) != 1:
            return False
    # Apply Rabin-Miller test.
    return RabinMiller(n)


def findPrime(bits=1024, tries=10000):
    # Find a prime with the given number of bits.
    x = 2**(bits - 1)
    y = 2*x
    for i in range(tries):
        n = random.randint(x, y)
        if n % 2 == 0:
            n += 1
        if isPrime(n):
            return n
    return None
    
def base_b_digits(x, b):
    # Builds a list of the base-b digits of x.
    digits = []
    n = x
    while(n > 0):
        r = n % b
        digits.append(r)
        n = (n - r) // b
    return digits

def isSquare(a, p):
    # Determines whether a is a square modulo p.
    # Assumes that p is an odd prime and a is coprime to p.
    return pow(a, (p - 1) // 2, p) == 1

def modularSqrt(a, p):
    # Returns a square root of a modulo p, if one exists.
    # Assumes that p is a prime congruent to 3 mod 4.
    if isSquare(a, p):
        return pow(a, (p + 1) // 4, p)
    return None
###############################33
import random, hashlib

class Signer:
    
    def __init__(self):
        self.publicKey, self.privateKey = (self.generateInformation())
    
    def generateInformation(self):
        # Generates public and private keys and saves them to a file.
        p = findPrime()
        q = findPrime()
        phi = (p - 1)*(q - 1)
        n = p*q
    
    
        foundEncryptionKey = False
        while not foundEncryptionKey:
            e = random.randint(2, phi - 1)
            if gcd(e, phi) == 1:
                foundEncryptionKey = True
    
        d = findModInverse(e, phi)
   
        publicInfo = {"n" : n, "e": e}
        privateInfo = {"n" : n, "d": d}
    
        return[(publicInfo),(privateInfo)]
        
    def getPublicKey(self):
        return self.publicKey
    
    def signMessage(self, message, eligible):
        if eligible == "y":
            return pow(message, self.privateKey['d'], self.publicKey['n'])
        else:
            return None
        
    def verifyVoter(self, eligible):
        pass
        
 
class Voter:
    def __init__(self, n, eligible):
        self.eligible = eligible
        
        foundR = False
        while not foundR:
            self.r = random.randint(2, n - 1)
            if gcd(self.r, n) == 1:
                foundR = True
        
    def blindMessage(self, m, n, e):
         
        blindMessage = (m * pow(self.r,e,n)) % n

        return blindMessage
         
    def unwrapSignature(self, signedBlindMessage, n):
        rInv = findModInverse(self.r, n)
        
        return ((signedBlindMessage * rInv) % n)
    
    def getEligibility(self):
        return self.eligible

def verifySignature(message, randNum, signature, publicE, publicN):
    return (int(hashlib.sha256((str(message) + str(randNum)).encode('utf-8')).hexdigest(),16) == pow(signature, publicE, publicN))        
        
import websocket
import hashlib
from tkinter import *
from tkinter.ttk import *
import random

class poll:
    def __init__(self, ws):
        self.ws = ws
        self.signer = Signer()
        self.publicKey = self.signer.getPublicKey()
        self.n = self.publicKey['n']
        self.e = self.publicKey['e']
        
    def poll_response(self, poll_answer, eligble_answer):
        
       
        if (poll_answer == 0): 
            poll_answer = 2


        if (eligble_answer == 0):
            eligble_answer = "n"
        if (eligble_answer == 1): 
            eligble_answer = "y"
       
        l = random.randint(1,self.n)
        message = poll_answer
        concat_message = str(message) + str(l)

        voter = Voter(self.n, eligble_answer)
        message_hash = hashlib.sha256(concat_message.encode('utf-8'))
        message_hash = message_hash.hexdigest()
        message_hash = int(message_hash,16)
        blindMessage = voter.blindMessage(message_hash, self.n, self.e)
#         print(1)
        print("Blinded message: " + str(blindMessage))
#         print(2)
        signedBlindMessage = self.signer.signMessage(blindMessage, voter.getEligibility())
        if signedBlindMessage == None:
            print("INELIGIBLE VOTER....VOTE NOT AUTHORIZED!")
        else:
            print("Signed blinded message: " + str(signedBlindMessage))
            signedMessage = voter.unwrapSignature(signedBlindMessage, self.n)
            decodedMessage = str(message)
            verificationStatus = verifySignature(message, l ,signedMessage, self.e, self.n)
            print("Signature: " + str(signedMessage))
            print("Decoded message: " + str(decodedMessage))
            print("Hashed message: " + str(hashlib.sha256((str(message)+str(l)).encode('utf-8')).hexdigest()))
            print("Verification status: " + str(verificationStatus))

       
class poll_machine:
    
    def __init__(self):
        websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp("ws://localhost:8888",
                                  on_message = self.on_message,
                                  on_error = self.on_error,
                                  on_close = self.on_close)
        
        self.p = poll(self.ws)
        self.master = Tk()
        self.master.configure(background='yellow')
        self.var_poll = IntVar()
        self.var_answer = IntVar()
        
        self.question_poll = Label(self.master, text="Vote for Trump or Obama?")
        self.yesBox_poll = Radiobutton(self.master, text="Trump", variable=self.var_poll, value=1)
        self.noBox_poll = Radiobutton(self.master, text="Obama", variable=self.var_poll, value=0)
        self.question_eligible = Label(self.master, text="Are you eligible to vote?")
        self.yesBox_eligible = Radiobutton(self.master, text="Yes", variable=self.var_answer, value=1)
        self.noBox_eligible = Radiobutton(self.master, text="No", variable=self.var_answer, value=0)
        self.submitButton = Button(self.master, text='Submit', command=self.make_vote)
        
        self.pollLabel = Label(self.master, text="Welcome to the Poll Booth")
        self.takePollButton = Button(self.master, text='Take Poll', command=self.reset_poll)
        self.pollLabel.grid(row=0, sticky=W, padx=10, pady=4)
        self.takePollButton.grid(row=1, sticky=W, padx=62)
        
    def on_message(self,ws, message):
        pass
    
    def on_error(self,ws, error):
        print ("error")

    def on_close(self,ws):
        print ("### closed ###")

    def on_open(self):
        self.master.title("Election Poll Demo")
        self.master.geometry('200x200')
        self.pollLabel.grid(row=0, sticky=W, padx=10, pady=4)
        self.takePollButton.grid(row=1, sticky=W, padx=62)
        
        self.master.mainloop()
        
    def make_vote(self):
        self.p.poll_response(self.var_poll.get(),self.var_answer.get())
        self.question_poll.grid_remove()
        self.yesBox_poll.grid_remove()
        self.noBox_poll.grid_remove()
        self.question_eligible.grid_remove()
        self.yesBox_eligible.grid_remove()
        self.noBox_eligible.grid_remove()
        self.submitButton.grid_remove()
        
        if self.var_answer.get() == 0:
            root = Tk()
            root.wm_title("Unsuccessful Vote")
            root.geometry('200x100')
            label = Label(root, text="Please try again!").grid(row=0, sticky=W)
            root.configure(background='red')
        else:      
            root = Tk()
            root.wm_title("Successful Vote")
            root.geometry('200x100')
            label = Label(root, text="Thanks for voting!").grid(row=0, sticky=W)
            root.configure(background='green')
        
        self.pollLabel.grid(row=0, sticky=W, padx=10, pady=4)
        self.takePollButton.grid(row=1, sticky=W, padx=62)
        
        
    def reset_poll(self):
        
        self.question_poll.grid(row=0, sticky=W, padx=50, pady=4)
        self.yesBox_poll.grid(row=1, sticky=W, padx=75)
        self.noBox_poll.grid(row=2, sticky=W, padx=75)
        self.question_eligible.grid(row=3, sticky=W, padx=20, pady=4)
        self.yesBox_eligible.grid(row=4, sticky=W, padx=75)
        self.noBox_eligible.grid(row=5, sticky=W, padx=75)
        self.submitButton.grid(row=6, sticky=W, pady=4, padx=62)
        
        self.pollLabel.grid_remove()
        self.takePollButton.grid_remove()

    def main(self):    
#         websocket.enableTrace(True)
       
        self.on_open()
#         self.ws.run_forever()
    
pm = poll_machine()
pm.main()


    



    
    


# In[ ]:




