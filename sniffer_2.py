"""
  The real stuff. 
"""

import socket,sys,struct

# Cria um socket de rede utilizando funções nativas do python
try:
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
	print('Socket could not be created.')
	sys.exit(1)

def get_mac_address(bytesString):
	bytesString = map('{:02x}'.format, bytesString)
	destination_mac = ':'.join(bytesString).upper()
	return destination_mac

def get_constants(prefix):
	# Cria um dicionário mapeando as constantes do módulo de socket para seus nomes
	return dict( (getattr(socket, n), n)
				for n in dir(socket)
				if n.startswith(prefix)
				)

protocols = get_constants('IPPROTO_')

with open("result.txt", "w") as file:
	file.write("\n")

# Enquanto o loop é executado infinitamente para capturar qualquer pacote de entrada
while True:

	# Escuta na porta 65565
	raw_data, address = sock.recvfrom(65565)
	destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])

	# Parâmetros do pacote
	destination_mac = get_mac_address(destination_mac)
	src_mac = get_mac_address(src_mac)
	ethernet_proto = socket.htons(ethernet_proto)
	# try:
	# 	ethernet_proto = protocols[ethernet_proto]
	# except:
	# 	ethernet_proto = "None"
	data = raw_data[14:]

	print('\nEthernet frame:')
	print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, ethernet_proto))
	# Cria o arquivo result.txt
	with open("result.txt", "a") as file:
		file.write('\nEthernet frame:')
		file.write('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, ethernet_proto))

	# Captura pacotes IPv4
	if (ethernet_proto == 8):
		version_header_len = data[0]
		version = version_header_len >> 4
		header_len = (version_header_len & 15) * 4
		ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
		# Captura o nome do protocolo
		try:
			proto = protocols[proto]
			proto = proto.split("_")[1] + " Protocol"
		except:
			proto = "None Specified"

		src = '.'.join(map(str,src)) 
		target = '.'.join(map(str,target)) 

		print('IPv4 packet:')
		print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
		print('\t{}, Source: {}, Target: {}'.format(proto,src,target))

		# Salva o resultado no arquivo result.txt
		with open("result.txt", "a") as file:
			file.write('\nIPv4 packet:')
			file.write('\n\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
			file.write(',{}, Source: {}, Target: {}\n'.format(proto,src,target))

		# Captura pacotes IPv6
		data = raw_data[14:]
		version_header_len = data[0]
		version = (version_header_len & 0xf0) >> 4
		header_len = version_header_len & 0x0f
		ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
		# Captura o nome do protocolo
		try:
			proto = protocols[proto]
			proto = proto.split("_")[1] + " Protocol"
		except:
			proto = "None Specified"
		src = '.'.join(map(str,src)) 
		numbers = list(map(int, src.split('.')))
		source = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
		target = '.'.join(map(str,target)) 
		numbers = list(map(int, target.split('.')))
		target = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)
		print('IPv6 packet:')
		print('\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_len, ttl))
		print('\t{}, Source: {}, Target: {}'.format(proto, source, target))

		# Salva o resultado no arquivo result.txt
		with open("result.txt", "a") as file:
			file.write('IPv6 packet:')
			file.write('\n\tVersion: {}, Header length: {}, TTL: {}'.format(version, header_len, ttl))
			file.write(',{}, Source: {}, Target: {}'.format(proto, source, target))

	print()
	with open("result.txt", "a") as file:
		file.write("\n")
