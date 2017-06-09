import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading
import ssl


#Variables

PORT = 443
HEADER_LENGTH = 2
usersonline={}

#End of Variables

#Functions


def SetupSslContext():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile="streznik.pem", keyfile="streznikkey.pem") #Load own certificate
    context.load_verify_locations('clients.pem')
    context.set_ciphers('AES128-SHA')
    return context


def ReceiveFixedLengthMsg(connStream, msgLen):
    try:
        msg = b''
        while len(msg) < msgLen:
            bajti = connStream.recv(msgLen - len(msg))
            if bajti == b'':
                raise RuntimeError("socket connection broken")
            msg = msg + bajti
        return msg
    except:
        connStream.close()
def ReceiveMessage(connStream):
    header = ReceiveFixedLengthMsg(connStream, HEADER_LENGTH)
    msgLen = struct.unpack("!H", header)[0]

    msg = None
    if msgLen > 0: # ce je vse OK
        msg = ReceiveFixedLengthMsg(connStream, msgLen)
        msg = msg.decode("utf-8")
    return msg

def SendMsg(connStream, msg):
    encodedMessage = msg.encode("utf-8")
    header = struct.pack("!H", len(encodedMessage))

    msg = header + encodedMessage
    connStream.sendall(msg);

#Main changes for SSL

def ClientThread(connStream, certData):
    global clients
    sender = certData['issuer'][5][0][1]
    print("[system] connected with " + sender)
    print("[system] we now have " + str(len(clients)) + " clients")
    while True:
        msg = ReceiveMessage(connStream)
        if "<msg>" in msg:
            msg = msg.replace("<msg><to>", " ")
            msg = msg.replace("</to><text>", " ")
            msg = msg.replace("</text></msg>", " ")
            msg2 = msg.split(" ")

            time = msg2[0]
            receiver  = msg2[1]
            actualMsg = msg2[2:]
            joined = "[" + sender + "]" + time + " " + ' '.join(actualMsg)
            if receiver != "global":
                if receiver not in usersonline:
                    SendMsg(usersonline[sender], "User not online")
                else:
                    for key in usersonline:
                        if key == receiver:
                            SendMsg(usersonline[receiver],joined)
            else:
                for client in clients:
                    SendMsg(client, joined)
                print("[RKchat]" + joined)
        else:
            usersonline[sender] = connStream
        if not msg:
            break;
    with clientsLock:
        clients.remove(connStream)
    print("[system] we now have " + str(len(clients)) + " clients")
    connStream.close()

#End of Functions

#Server start

print("Server is starting!")

mySslCtx = SetupSslContext() #SSL setup

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(("localhost", PORT))
serverSocket.listen(1)

print("[system] listening ...")
clients = set()
clientsLock = threading.Lock()

while True:
    try:
        clientSock, clientAddr = serverSocket.accept()

        try:
            connStream = mySslCtx.wrap_socket(clientSock, server_side=True) #SSL wrap
            certData = connStream.getpeercert()
            with clientsLock:
                clients.add(connStream)
            SendMsg(connStream,"Welcome " + certData['issuer'][5][0][1] + " with valid SSL certificate to te RKchat")
            thread = threading.Thread(target=ClientThread, args=(connStream, certData));
            thread.daemon = True
            thread.start()
        except:
            connStream.close()
            clientSock.close()
    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
serverSocket.close()
