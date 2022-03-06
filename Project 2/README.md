UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the
project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router`
implementation.  The starter code includes only the framework to receive raw
Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job
is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create
the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz`
turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub]
(https://github.com/), [GitLab](https://gitlab.com), or other places.  At the
same time, you are PROHIBITED to make your code for the class project public
during the class or any time after the class.  If you do so, you will be violating
academic honestly policy that you have signed, as well as the student code of
conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually
stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3
(https://bitbucket.org/cs144-1617/lab3).



## Team members
1. Puvali Chatterjee / UID 504822474
2. Nandini Chitale / UID 704099273



## The contribution of each member
We worked on the logic of the implementation together. We divided parts of the
work of writing the code and we wrote the other parts by pair programming. We tested
the code both together and separately on our own machines.



## High level design of our implementation
The simple router works by receiving raw Ethernet frames and then creating new frames
and handling and forwarding packets to the correct interfaces. The handlePacket method
in the simple-router.cpp files takes a packet and an interface as an argument.

* If the interface of the packet is unknown, the packet is ignored.

* Subsequently, the program examines the ethertype field of the packet's headers to
identify whether it is an IP packet or an ARP packet since both types of packets are
handled differently. Packets that are neither IP nor ARP are discarded/ignored.

* If it is an incoming ARP request, the program constructs an ARP reply packet with the
appropriate Ethernet headers and ARP headers and sends it to the intended target if the
target IP matches the Ethernet IP. If it is an incoming ARP reply, the program inserts
an entry into the ARP cache and sends the requested packets corresponding to the received
ARP reply.

* Otherwise, if the packet is an IP packet, the program checks its validity by ensuring
that its header checksum matches the calculated checksum since. Packets smaller than 20
bytes are ignored since the minimum length for IP packets is 20 bytes.

* If the IP packet destined to the router contains an ICMP payload of type 8, then the ICMP
checksums are verified and an echo reply is constructed and sent in response to this ping.
If the packet does not contain an ICMP payload, it is discarded and a 'Port Unreachable'
message is sent since there is no way to respond to the ping. If the IP packet contains a
UDP or TCP payload, a 'Port Unreachable' message is constructed and sent.

* If the IP packet is not destined to the router, then it must be forwarded to the correct
interface. Its time-to-live and checksums are updated. If the time-to-live is now 0, a 'Time Exceeded' message is sent to the sender and the packet is not forwarded. If a corresponding MAC address for
the packet's IP address can be found, the packet is forwarded to its interface. If the
MAC address cannot be found, an ARP request is queued using the appropriate gateway address
and routing table entry.

* Other functions performed by the program include the removal of stale ARP cache entries,
resending ARP requests, applying the longest prefix match algorithm to find an entry in
the routing table, etc.



## Problems we ran into and how we solved them
One problem we ran into was with traceroute. When running traceroute from the client
to the router, the router was supposed to send back a destination port unreachable
message (which takes the form of an ICMP type 3 packet). This ICMP packet was supposed
to have the IP header and 64 bits of the original data datagram within its "data"
field, but due to mistakenly using the wrong intermediate variable ("ip_to_send"), the
IP header in the data field was incorrect, and traceroute wasn't working. So, this
was fixed by using the correct intermediate variable ("ip_received"). However,
another problem remained: when running a traceroute command from the client to one
of the routers' interfaces that was *not* facing the client (192.168.2.1 or 172.64.3.1),
the mininet console printed out the interface facing the client (10.0.1.1) as the output
from traceroute. This was fixed by setting the outbound packet's source IP address
to the inbound packet's destination IP address (instead of setting it to the IP address
of the router's interface on which the packet was received). 

Another problem we ran into was with packet forwarding. Once we had implemented all
of the logic needed for packet forwarding, the router was receiving and forwarding
packets (based on the router log), but these packets were not being received at their
destination. We pinpointed the problem to the destination MAC address in the ethernet
header of the packet being forwarded from the router. The second argument in the call
to memcpy() was missing a \[0\]. Once this was fixed, the packet forwarding operation
succeeded.
