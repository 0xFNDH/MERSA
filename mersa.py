
# Multicast Encrypted Reverse Shell Application

# server <-Ask- Client
# server -send public key-> client
# server <-send public key- client
# server -encrypted data-> client
# server <-encrypted data- client

# todo: store generated pem
# todo: send recv after key exchange

import socket
import time
import hashlib
import sys
import threading
import struct
import os
import queue
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def rsa_private_key(bit=2048):
  return RSA.generate(bit)

def encrypt(plaintext, public_key):
  cipher = PKCS1_OAEP.new(public_key)
  ciphertext = cipher.encrypt(bytes(plaintext))
  return ciphertext

def decrypt(ciphertext, private_key):
  cipher = PKCS1_OAEP.new(private_key)
  return cipher.decrypt(ciphertext)

def IPv4LAN():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    s.connect(("255.255.255.255", 1))
    IP = s.getsockname()[0]
  except Exception:
    IP = "127.0.0.1"
  finally:
    s.close()
  return IP

def IPv6LAN():
  s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
  try:
    s.connect(("ff02::fb", 1))
    ipv6 = s.getsockname()[0].split("%")
  except Exception:
    ipv6 = "::1"
  finally:
    s.close()
  return ipv6

class MERSA_KeyExchange():

  def __init__(self, address="224.0.0.251", port=5000, pubkey=None, prvkey=None):
    self.address = address
    self.port = port
    self.sessions = {
            "0.0.0.0": {
                    "PrivateKey":prvkey,
                    "PublicKey":pubkey,
                    "TTL":"12:00:00 30 Nov 23"
            }
    }
    self.options = {
            "SEND-PUB":b"\x01", # Request publickey
            "TAKE-PUB":b"\x02", # Send publickey
            "DATA-PUB":b"\x03", # Data
            "PLAINTEXT":b"\x04" # Plaintext Data
    }
    self.ID = self.ip_ID(IPv4LAN())

  def ip_ID(self, ip):
    """\
    Returns the last two octets of an IPv4 address as bytes
    192.168.25.28 => \\x19\\x1c
    """
    return (lambda x,y:bytes([int(x)])+bytes([int(y)]))(ip.split(".")[-2],ip.split(".")[-1])

  def multicast_socket(self, ttl=None, port=None):
    multi = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multi.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    multi.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    multi.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 255)
    multi.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, 1)

    if type(port) == int:
      multi.bind((self.address, port))
      multi.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack("4sl", socket.inet_aton(self.address), socket.INADDR_ANY))

    multi.settimeout(ttl)
    return multi

  def validate_header(self,header,ip,opt=None):
    """\
    Returns 'True' if the packet being tested is a MERSA packet.
    MERSA Packet Formatting
    \\x00\\x90\\x00{option}{3th octet}{4th octet}
    """
    if header[:3] == b"\x00\x90\x00" and header[-2:] == self.ip_ID(ip):
      if opt != None:
        return bytes([header[-3]]) == opt
      return True
    else:
      return False

  def make_expiration(self, days=1):
    TTL = time.strftime("23:59:59 %d %b %y").split(" ")
    TTL[1] = str(int(TTL[1])+days)
    TTL = " ".join(TTL)
    return TTL

  def make_key(self, bits=2048):
    """\
    Generates a key pair for server (0.0.0.0) in self.sessions.
    """

    prvkey = rsa_private_key(bits)
    TTL = self.make_expiration()

    self.sessions.update({"0.0.0.0":{
            "PrivateKey":prvkey,
            "PublicKey":prvkey.publickey(),
            "TTL":TTL
    }})

  def broadcast_publickey(self, ttl=2.0):
    ms = self.multicast_socket(ttl)
    for _ in range(2):
      ms.sendto(b"\x00\x90\x00" + self.options["TAKE-PUB"] + self.ID + self.sessions["0.0.0.0"].get("PublicKey").exportKey() ,(self.address, self.port))
      time.sleep(ttl)
    ms.close()

  def recieve_publickey(self, ttl=10.0):
    ms = self.multicast_socket(ttl, self.port)
    ttl_hello = time.time()+ttl
    while time.time() < ttl_hello:
      try:
        data, addr = ms.recvfrom(2056)
        if self.validate_header(data[:6], addr[0], self.options["TAKE-PUB"]) == True:
          if verbose:
            print(f"[2-A] Recieved PublicKey from {addr[0]}")
          if addr[0] not in self.sessions.keys():
            pubkey = RSA.importKey(data[6:])
            self.sessions.update({addr[0]:{"PublicKey":pubkey,"TTL":None}})
            if verbose:
              print(f"[2-B] Added PublicKey from {addr[0]} to sessions")
            break
      except Exception as error:
        raise error
        print(error,file=sys.stderr)
        ms.close()
        sys.exit()
    ms.close()

  def recv_data(self, ttl=10.0):
    ms = self.multicast_socket(ttl)
    ttl_hello = time.time()+ttl
    while time.time() < ttl_hello:
      data, addr = ms.recvfrom(2056)
      if self.validate_header(data[:6], addr[0], self.options["DATA-PUB"]) and addr[0] in self.sessions.keys() and self.ID == data[-2:]:
        message = decrypt(data[6:], self.sessions["0.0.0.0"].get("PrivateKey"))
        print(message)

  def send_data(self, payload, dst, ttl=2.0):
    ms = self.multicast_socket(ttl)
    if dst in self.sessions.keys():
      enc_data = encrypt(payload, self.sessions[dst].get("PublicKey")) + self.ip_ID(dst)
      ms.sendto(enc_data, (self.address, self.port))
    ms.close()

_privatekey = None
_publickey = None

for arg in sys.argv:
  if os.path.isfile(arg) and "pem" in arg:
    with open(arg,"rb") as pem:
      _privatekey = RSA.importKey(pem.read())
      _publickey = _privatekey.publickey()
    break

if type(_privatekey) == type(None):
  _privatekey = rsa_private_key(2048)
  _publickey = _privatekey.publickey()

_shell = "-s" in sys.argv
_host = "-h" in sys.argv
_auto_broadcast = "-a" in sys.argv
verbose = "-v" in sys.argv

lock = threading.Lock()

def prints(data, out=sys.stdout):
  lock.acquire()
  print(data, file=out)
  lock.release()

if __name__ == "__main__":
  mersa = MERSA_KeyExchange(pubkey=_publickey, prvkey=_privatekey)
  mersa.broadcast_publickey()
  mersa.recieve_publickey()
