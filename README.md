# MERSA
Multicast Encrypted Reverse Shell Application (MERSA)

MERSA was developed during a penetration test where information on a compromised device was unable to be sent over the internal network due to point-to-point restrictions. However, multicast was not disabled and that allowed for data to be sent over the network.

MERSA takes advantage of multicast as a vector for exchanging information by establishing a sudo-TLS communication between client and server.

> Version 1.0 provides the base framework for key exchange and multicast communication using python 3

## Example Client Version 1.0

```python
# Client
import mersa
from Crypto.PublicKey import RSA

PrivateKey = RSA.importKey(open("private.pem","rb").read())
PublicKey = PrivateKey.publickey()

MERSA = mersa.MERSA_KeyExchange(pubkey=PublicKey, prvkey=PrivateKey)
MERSA.broadcast_publickey()
MERSA.recieve_publickey()

soc = MERSA.multicast_socket(3, 5000)

while True:
  try:
    data, addr = soc.recvfrom(2056)
    if addr[0] in MERSA.sessions.keys():
      print(f"Message from {addr[0]}:{addr[1]}")
      print(mersa.decrypt(data, MERSA.sessions["0.0.0.0"]))
      print("\n")
    else:
      print(f"Requesting keys from {addr[0]}:{addr[1]}")
      MERSA.broadcast_publickey()
      MERSA.recieve_publickey()
  except KeyboardInterrupt:
    soc.close()
    break
  except:
    pass
  
  # ToDo: Send options (a,b,c,*)
```

> MERSA was developed from Tremeris-Kynigoskylo (TK-PoC) Project
