# Multicast Encrypted RSA (MERSA)
```csharp
   o       .                         o      .
                      .
  .   dBBBBBBBb dBBBBP dBBBBBb  dBBBBP dBBBBBb 
     dB'   'dP dB     dB  dBP dBP'         'BB 
    dB'dB'dB' dBBP   dBBBBP' 'BBBBb   dBBBPBB'  .
   dB'dB'dB' dBP    dBP  BB     dBP  dBP   BB' 
  dB'dB'dB' dBBBBP dBP  dB  dBBBBP' 'dBBBBBB' 
     .                                          
                                .
         .         o    
                                        .
  .      |      
       --o--      MERSA-FULLY      .
         |                                   o
 o             .
```

# Overview

 - [Documentation](./README.md#About)
 - [PoC Testing Tools](./PoC/)
 - [Configuration Solutions](./README.md#Patching)
 - [Additional Information](./README.md#Resources)

# About

Multicast Encrypted RSA (MERSA) and Multicast Encrypted Low Operations Shell (MELOS) are PoC tools that demonstrate how multicast can be used to undermine network security policies and bypass point-to-point network restrictions.

Multicast-Tunneling is a vulnerability that is not specific to any vendor and affect networks without proper controls for multicast traffic. Multicast uses protocols IGMP (L2) or PIM (L3) to route packets and can enable communication with devices that are on network segments with restricted access. If multicast routing is not secured, certain network security policies may be circumvented as a result.

Multicast traffic restrictions are often neglected, creating a potential risk that could go unnoticed. The primary goal of MERSA is to highlight the vulnerabilities posed by multicast-enabled networks. The best way to minimize the risks associated with multicast, is to disable it within the router's configuration files. In the case that disabling multicast is not feasible, extra measures can be taken to ensure multicast traffic is contained.

# Patching

> Please consult your network administrator prior to making any changes to router configurations. Making unscheduled modifications to the configurations can have adverse effects on the services or devices operating within the network.

**How to disable multicast for Cisco IOS XE 3.2SE+**

```ruby
! Disable all multicast traffic
router(config)# no ip multicast-routing

! Disable multicast on a specific interface
router(config)# interface gigabitethernet 0/0/0
router(config-if)# no ip igmp
router(config-if)# no ip multicast-routing
router(config-if)# end
```

**How to log multicast interactions for Cisco IOS XE Everest 16.6.1+**
```ruby
! Permit a range for allowed multicast channels
router(config)# ip igmp profile 40
router(config-igmp-profile)# permit
router(config-igmp-profile)# range 224.1.1.1 233.255.255.255
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

# Additional Information

## Attack Scenario
Imagine that you are in a network that hosts a webserver, but due to network restrictions, you cannot interact with it or observe its traffic. By launching an attack on the external webpage and acquiring code execution, you can utilize MELOS to gain a reverse shell. This will enable you to exfiltrate files and data through the network to your device without being denied by the current policies. The use of MELOS and MERSA will depend on factors such as the network type, current configurations, and the number of security layers in place. However, if remote code execution is already established, it's probable that multicast has been not considered in the network's security measures.

## Tremeris Kynigoskylo
MERSA is a less potent iteration of the Tremeris Kynigoskylo (TK-PoC) software. It poses a significantly lower risk and can be easily detected through various network intrusion detection systems and network monitoring applications. Unlike its predecessor, the TK-PoC project was created to covertly extract  files from internal networks without raising any red flags or displaying any unusual activity.
Multicast was used as one of the traffic types for TK-PoC to obfuscate files and data into as it was able to bypass network restrictions.
Additionally, without multicast logging enabled, it is notably more difficult to locate the specific device(s) that received the extracted files from within the network. This research has lead to creation of MERSA as a public tool designed to test multicast restrictions.

## Resources

> [Cisco Multicast Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/command_reference/b_1612_3850_cr/ip_multicast_routing_commands.html)
