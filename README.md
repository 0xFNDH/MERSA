# MERSA
Multicast Encrypted Reverse Shell Application (MERSA)

MERSA was developed during a penetration test where information on a compromised device was unable to be sent over the internal network due to point-to-point restrictions. However, multicast was not disabled and that allowed for data to be sent over the network.

MERSA takes advantage of multicast as a vector for exchanging information by establishing a sudo-TLS communication between client and server.

> Version 1.0 provides the base framework for key exchange and multicast communication using python 3
