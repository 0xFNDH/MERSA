# Multicast Encrypted Reverse Shell Application (MERSA)
```
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
```

Multicast Encrypted Reverse Shell Application (MERSA) is a POC tool that demonstrates how multicast can be used to bypass point-to-point restrictions on secured network.

MERSA is a non-vendor specific vulnerability that undermines network security policies by operating on multicast. Multicast uses IGMP (L2) or PIM (L3), depending on the type of network, to route multicast traffic. As a result, some networks' security policies can be bypassed due to gaps in the security controls for multicast routing.

Multicast is often forgetten about and rarely utilized within most networks. As a result, it can be overlooked as a vulnerability. The goal of MERSA is to bring attention to the existing security gaps in networks that have multicast enabled. The best way to mitigate any risks against multicast, is to disable it in the router configuration file.

# Tremeris Kynigoskylo

> MERSA is a less potent iteration of the Tremeris Kynigoskylo (TK-PoC) software. It poses a significantly lower risk and can be easily detected through various network intrusion detection systems and network monitoring applications. Unlike its predecessor, the TK-PoC project was created to covertly extract  files from internal networks without raising any red flags or displaying any unusual activity.
> Multicast was used as one of the traffic types for TK-PoC to obfuscate files and data into as it was able to bypass network restrictions.
> Additionally, without multicast logging enabled, it is notably more difficult to locate the specific device(s) that received the extracted files from within the network.

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

**Additional Resources**

> [Cisco Multicast Commands](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3850/software/release/16-12/command_reference/b_1612_3850_cr/ip_multicast_routing_commands.html)
