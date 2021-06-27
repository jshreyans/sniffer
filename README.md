# Packet Sniffer (WIP)

This work aims to implement an improvement in a project available in the free software community. The job is pre-requisite to packet network packets.
The main objective of this work is to contribute to the software development and the free software community, adding functions to a software available for free and collaborating with the evolution of tools and study possibilities, as well as practicing the concepts of the discipline during a stage of Implementation .

## What is a packet sniffer for?
Any conventional network carries data in packets that are manufactured by one server (or computer) and sent out to one or more servers on the same network. For security reasons or to just be nosy, one might want to analyse the traffic that such a network produces. This means keeping track of the packets that travel across the network by "sniffing" or detecting them and decoding their content.

To understand the code, you might want to develop a basic understanding of [sockets](https://medium.com/swlh/understanding-socket-connections-in-computer-networking-bac304812b5c). The program is made using the Python [Socket API](https://docs.python.org/3/library/socket.html).

## Tool features
The current Python implementation captures IPv4 and IPv6 packets and provides the following info:
- Destination and Source MAC address
- Ethernet Protocol 
- TTL (Time-to-Live)
- Header length
- Improved presentation of sniffer results, identifying protocol patterns, for example, instead of displaying “Protocol 6”, displaying “TCP protocol”;
- Identification and treatment for ICMP protocol;
- Improved handling of TCP protocol;
- Identification and treatment for UDP protocol;
- Add an IPV6 packet handling capability;
- Save the output to file or screen to facilitate further analysis;

## To run:
In its current state, the program requires a Linux machine and Python3 installed.   
You'll need to use root privileges to run. The command I'm using:

sudo su python3 sniffer_2.py
