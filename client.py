#Client A in NS protocol
import socket
import sys
import random
from time import sleep
import des
import library

#Assume for this assignment both clients know these
HOST = "127.0.0.1"
PORT = 5010

KDC_key = None
MyId = None

#method for printing the options for the client
def printMenuOptions():
    print("OPTIONS:")
    print("\t Enter 'quit' to exit")
    print("\t Enter 'list' to list established secure users")
    print("\t Enter 'connect|id to connect to id")

# method that creates a random 10 bit key
def random10bit():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return int(num,2)

#method that creates a random 10 bit number as a string to serve as our nonce
def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num

#method that performs the NS protocol
def needhamSchroeder(soc):
    message = soc.recv(1024).decode('utf8')

    #decrypting the message
    decrypedMessage = library.decrypt(message,KDC_key)
    Ks = decrypedMessage[0:10]
    IDb = decrypedMessage[10:18]
    T = decrypedMessage[18:28]
    smallEncryption = decrypedMessage[28:]
    #now we connect to client B 
    mySocket = socket.socket()
    mySocket.connect((HOST,PORT))
    mySocket.send(smallEncryption.encode())
   
    newNonce = mySocket.recv(1024).decode()
    #decrypting nonce recieved from B
    decryptedNonce = library.decrypt(newNonce,Ks)
    #turning it into and int
    changedNonce = int(decryptedNonce,2)
    #subtracting 1: function that is predetermined by A and B
    changedNonce = changedNonce - 1
    # binary string
    changedNonce = bin(changedNonce)[2:].zfill(10)
    #encrypting f(nonce)
    encryptedNonce = library.encrypt(changedNonce, Ks)
    mySocket.send(encryptedNonce.encode())
     
    # Begin secure chat!
    if mySocket.recv(1024).decode() == "VERIFIED":
        print("***Client A***")
        while message != "quit":

            message = input("Enter the message: -> ")
            #encrypting the message using DES
            finalEncryptedMessage = library.encrypt(message,Ks)

            
            #sending the message
            mySocket.send(finalEncryptedMessage.encode())
            #receiving the response from the other user
            data = mySocket.recv(1024).decode()
            #decrypting the other user's message
            decryptedMessage = library.decrypt(data,Ks)
            if(decryptedMessage == "quit"):
                    print("Ending the chat...goodbye!")
                    mySocket.close()
                    sys.exit()
            print("Message from B :"+str(decryptedMessage))
#
    elif(message == "quit"):
    	mySocket.send(message.encode("utf8"))
    	print("Closing the client. Thanks!")
    	mySocket.close()
    	sys.exit()
    #continue
            
        
#Diffie Helman key exchange for the client
def diffieHelman(kdc, PrivateKey):
    #Public G and P from server
    message = kdc.recv(1024).decode('utf8')
    message = message.split("|")
    # print(message)
    publicP, publicG = int(message[1]),int(message[2])
    global MyId
    MyId = message[0]


    #receives the first calculation
    #call this X
    A = int(kdc.recv(1024).decode('utf8'))

    #generate 10 bit key for KDC
    #call this a
    #B = g^b mod p
    b = random10bit()
    B = (publicG**b)%publicP

    #now we send this to the server
    kdc.send(str(B).encode())

    #S = A^b mod p
    S = (A**b)%publicP
    global KDC_key
    KDC_key = bin(S)[2:].zfill(10)
    print("Established key = ", str(S))


def main():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 5000

    try:
        soc.connect((host, port))
    except:
        print("Connection Error!!")
        sys.exit()

    #Generate key and use it in function call
    Key = random10bit()
    diffieHelman(soc,Key)

    while True:
        #print the user options
        printMenuOptions()
        message = input(" -> ")
        
        
        if 'connect' in message:
            print("Wait!!Trying to connect")
            otherUser = message.split("|")[1]
            message = 'connect|' + MyId + otherUser + nonceGenerator()
            
        soc.send(message.encode("utf8"))

        if 'connect' in message:
            #go up to the NS method and start the interaction
            needhamSchroeder(soc)

        if message == "quit":
            break

        #showing the user other users availabe
        if message == "list":
            soc.send(message.encode("utf8"))
            userList = soc.recv(1024).decode('utf8')
            print(userList)
        
        if soc.recv(5120).decode("utf8") == "-":
            pass   # null operation
        
            
    soc.send(b'--quit--')

if __name__ == "__main__":
    main()