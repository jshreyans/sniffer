"""
  The real stuff. 
"""

import socket,sys,struct

# create a network socket using the default constructor
try:
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
  print('Socket could not be created.')
  sys.exit(1)

def get_mac_address(bytesString):
  bytesString = map('{:02x}'.format, bytesString)
  destination_mac = ':'.join(bytesString).upper()
  return destination_mac

def get_header_name(nextHeader):
    if nextHeader == 0:
        return 'Hop-by-Hop Options header'

    elif nextHeader == 6:
        return 'TCP'

    elif nextHeader == 17:
        return 'UDP'

    elif nextHeader == 41:
        return 'Encapsulated IPv6 header'

    elif nextHeader == 43:
        return 'Routing header'

    elif nextHeader == 44:
        return 'Fragment header'

    elif nextHeader == 50:
        return 'Encapsulating Security Payload header'

    elif nextHeader == 51:
        return 'Authentication header'

    elif nextHeader == 58:
        return 'ICMPv6'

    elif nextHeader == 59:
        return 'No next header'

    elif nextHeader == 60:
        return 'Destination Options header'

    else:
        return 'Unidentified'

def get_ipv6_next_headers(packet, nextStr, nextHeader):
    if nextHeader == 0:
        headerPacket = struct.unpack("!2b", data[0:2])
        payloadLenght = headerPacket[1]
        packet = packet[int(payloadLenght * 8 + 8):]
        get_ipv6_next_headers(packet, nextStr + " > " + get_header_name(headerPacket[0]), headerPacket[0])

    elif nextHeader == 6:
        return nextStr

    elif nextHeader == 17:
        return nextStr

    elif nextHeader == 41:
        return nextStr

    elif nextHeader == 43:
        headerPacket = struct.unpack("!4B", data[0:4])
        payloadLenght = headerPacket[1]
        packet = packet[int(payloadLenght * 8 + 8):]
        get_ipv6_next_headers(packet, nextStr + " > " + get_header_name(headerPacket[0]), headerPacket[0])

    elif nextHeader == 44:
        headerPacket = struct.unpack("!2B1H1I", packet[0:8])
        packet = packet[8:]
        get_ipv6_next_headers(packet, nextStr + " > " + get_header_name(headerPacket[0]), headerPacket[0])

    elif nextHeader == 50:
        return nextStr

    elif nextHeader == 51:
        headerPacket = struct.unpack("!2b", data[0:2])
        payloadLenght = headerPacket[1]
        packet = packet[int(payloadLenght * 4 + 8):]
        get_ipv6_next_headers(packet, nextStr + " > " + get_header_name(headerPacket[0]), headerPacket[0])

    elif nextHeader == 58:
        return nextStr

    elif nextHeader == 59:
        return nextStr

    elif nextHeader == 60:
        headerPacket = struct.unpack("!2b", data[0:2])
        payloadLenght = headerPacket[1]
        packet = packet[int(payloadLenght * 8 + 8):]
        get_ipv6_next_headers(packet, nextStr + " > " + get_header_name(headerPacket[0]), headerPacket[0])

    else:
        return nextStr

# while loop runs infinitely to capture any incoming packets
while True:

  # listen on port 65565
  raw_data, address = sock.recvfrom(65565)
  destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])

  # packet parameters
  destination_mac = get_mac_address(destination_mac)
  src_mac = get_mac_address(src_mac)
  ethernet_proto = socket.htons(ethernet_proto)
  data = raw_data[14:]

  print('\nEthernet frame:')
  print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, ethernet_proto))

   # analyse only IPv4 packets (I know IPv6 is the real deal but this should work for now)
  if (ethernet_proto == 8):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    src = '.'.join(map(str,src))
    target = '.'.join(map(str,target))

    print('IPv4 packet:')
    print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
    print('\tProtocol: {}, Source: {}, Target: {}'.format(proto,src,target))

  # analyse IPv6 packets
  if (ethernet_proto == 56710):
      firstWord, payloadLength, nextHeader, hoplimit = struct.unpack(
          ">IHBB", data[0:8])
      source = socket.inet_ntop(socket.AF_INET6, data[8:24])
      destination = socket.inet_ntop(socket.AF_INET6, data[24:40])

      bin(firstWord)
      "{0:b}".format(firstWord)

      version = firstWord >> 28
      trafficClass = int(firstWord >> 16) & 4095
      flowLabel = int(firstWord) & 65535

      print('-=-=-=-=-=-=-=-= IPV6 -=-=-=-=-=-=-=-=')
      print('Payload lenght:' + str(payloadLength))
      print('Hop limit:' + str(hoplimit))
      print('version:' + str(version))
      print('Traffic class:' + str(trafficClass))
      print('Flow label:' + str(flowLabel))
      print('Source:' + str(source))
      print('Destination:' + str(destination))
      nextHeader = get_ipv6_next_headers(data[40:], get_header_name(nextHeader), nextHeader)
      print('Next headers:' + nextHeader)