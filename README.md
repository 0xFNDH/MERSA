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
       --o--    We in your walls   .
         |                                   o
 o             .
```

Multicast Encrypted Reverse Shell Application (MERSA) is a POC tool that demonstrates how multicast can be used to bypass point-to-point restrictions on secured network.

MERSA is a non-vendor specific vulnerability that undermines network security policies by operating on multicast. Multicast uses IGMP (L2) or PIM (L3), depending on the type of network, to route multicast traffic. As a result, some networks' security policies can be bypassed due to gaps in the security controls for multicast routing.

Multicast is often forgetten about and rarely utilized within most networks. As a result, it can be overlooked as a vulnerability. The goal of MERSA is to bring attention to the existing security gaps in networks that have multicast enabled. The best way to mitigate any risks against multicast, is to disable it in the router configuration file.
