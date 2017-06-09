import socket
import struct
import sys
import threading
import datetime
import ssl

#Variables

PORT = 443
SERVERNAME = 'localhost'
HEADER_LENGTH = 2

#End of Variables

#Functions

def SetupSslContext(cert, key):
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	context.verify_mode = ssl.CERT_REQUIRED
	context.load_cert_chain(certfile = cert, keyfile = key)
	context.load_verify_locations('streznik.pem')
	context.set_ciphers('AES128-SHA')

	return  context

def ReceiveFixedLengthMsg(connStream, msgLen):
	msg = b''
	while len(msg) < msgLen:
		chunk = connStream.recv(msgLen - len(msg))
		if chunk == b'':
			raise RuntimeError("socket connection broken")
		msg = msg + chunk

	return msg

def ReceiveMessage(connStream):
	header = ReceiveFixedLengthMsg(connStream, HEADER_LENGTH)
	msgLen = struct.unpack("!H", header)[0]

	msg = None
	if msgLen > 0:
		msg = ReceiveFixedLengthMsg(connStream, msgLen)
		msg = msg.decode("utf-8")

	return msg

def SendMsg(connStream, msg):
	encodedMsg = msg.encode("utf-8")

	header = struct.pack("!H", len(encodedMsg))

	msg = header + encodedMsg

	connStream.sendall(msg);

def messageListener():
	while True:
		msgReceived = ReceiveMessage(connStream)
		if len(msgReceived) > 0:
			print("[RKchat] " + msgReceived)

def Msg():
	receiver = input("input receiver ('global' for global chat):")
	time = "(" + datetime.datetime.now().strftime("%H:%M:%S") + ")"
	actualMsg = input("message:")
	packed = time+"<msg><to>"+receiver+"</to><text>"+actualMsg+"</text></msg>"

	return packed

def First():
	msg = ' '
	return msg

#End of Functions

print("[system] connecting to chat server ...")
i = input("input username who has .pem file: ")
cert = i + ".pem"
key = i + "key.pem"

x = SetupSslContext(cert,key) #SSL setup

connStream = x.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=False) #SSL wrap
connStream.connect((SERVERNAME, PORT))

data = connStream.getpeercert()
sName = data['issuer'][5][0][1]

print("[system] connected to", sName , "on port", PORT)


thread = threading.Thread(target=messageListener)
thread.daemon = True
thread.start()
SendMsg(connStream, First())



while True:
	try:
		SendMsg(connStream, Msg())
	except KeyboardInterrupt:
		sys.exit()
