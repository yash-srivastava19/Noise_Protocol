import socket
from noise.connection import NoiseConnection

sock = socket.socket()
sock.connect(('localhost', 2000))

# Setting up a NoiseConnection instance - with NN handshake pattern, Curve 25519(for elliptic curve keypair), ChaChaPoly1305 as cipher function 
# and SHA256 for hashing

proto = NoiseConnection.from_name(b'Noise_NN_25519_ChaChaPoly_SHA256')
proto.set_as_initiator()
proto.start_handshake()

# As we are the initiator, we need to generate first message.
message = proto.write_message()

sock.sendall(message)
received = sock.recv(2048)

payload = proto.read_message(received)

# At this point, the handshake should be finished. We can now use encrypt/decrypt methods of NoiseConnection now for encryption
encrypted_message = proto.encrypt(b'This is a blah blah message')
sock.sendall(message)

ciphertext = sock.recv(2048)
print(f'CipherText : {ciphertext}')

plaintext = proto.decrypt(ciphertext)
print(f'PlainText : {plaintext}')