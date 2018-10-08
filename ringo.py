import socket
import struct
import time
import math
import time
import threading
import operator
import sys
import itertools
import random
import errno
import struct
import binascii
import base64
from pathlib import Path
from checksum import verify_checksum, verify_ip_checksum, verify_udp_checksum
from packet import Packet
from packet import ControlType
from enum import Enum


BUFFER_SIZE = 2048  # if you change this to 512, parts from first assignment fail as  more than 512 bytes is sent in some instances.
DATA_PER_PACKET = 475

class PathDirection(Enum):
	CLOCKWISE = 1
	COUNTER_CLOCKWISE = 2


class Ringo:
	def __init__(self, flag, local_port, poc_host, poc_port, n):
		self.role = flag
		self.local_host = socket.gethostname()
		self.local_port = local_port
		self.poc_host = poc_host
		self.poc_port = poc_port
		self.n = n
		self.peers = set()  # {(ip, port), (ip, port)}
		self.rtt_vector = {}  # reset if optimal path changes after file transfer is complete
		self.roles = {}  # {{ip, port}: <role>}  
		self.rtt_matrix = {}  # reset if optimal path changes after file transfer is complete
		self.active_ringos = set()
		self.conn_send = False # reset when optimal path effected by offline ringos (has to be done during file transfer)
		self.conn_recv = False #reset when optimal path effected by offline ringos (has to be done during file transfer)
		self.data_recvd = bytes() # receiver
		self.path = []  # reset when optimal path effected by offline ringos (has to be done during file transfer)
		self.peers_ready = set()  # reset when optimal path effected after file transfer is complete
		self.starting_seq_no = random.randint(1, 1000000000) # sender
		self.bytes_sent_successfully = 0 # sender
		self.data_tx_rtt = 0 # reset when optimal path effected by offline ringos (has to be done during file transfer)
		self.got_nack = False # sender
		self.last_data_recvd = bytes() # receiver
		self.file_received = "" # receiver
		self.fin_sent = False # sender
		self.keep_alive_port = 18000  # user input port must be different
		self.active_ringo_map = {}

	# Ping
	def peer_discovery(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(3)  # 3 seconds
		# keep track of peers pinged so far
		peer_discovery_map = {}
		while len(peer_discovery_map) < self.n - 1 or (min(list(peer_discovery_map.items()), key=operator.itemgetter(1))[1] < self.n-1 if peer_discovery_map else True):
			msg = "Peer Discovery/" + self.local_host + ":" + str(self.local_port)
			# starting ringo doesn't have a PoC; wait until there is a peer
			if self.poc_host == "0" and len(self.peers) == 0:
				continue
			
			# base case: ringo only has a PoC and no peers
			elif self.poc_host != "0" and len(self.peers) == 0:
				addr = (self.poc_host, self.poc_port)
				msg += "," + self.poc_host + ":" + str(self.poc_port)
				success = False
				while not success:
					try:
						data = base64.b64encode(msg.encode('utf-8'))
						packet = Packet(addr[1], self.local_port, socket.gethostbyname(addr[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, data, 0, 0)
						packet.assemble_packet()
						_ = s.sendto(packet.raw, addr)
						data_sent, _ = s.recvfrom(65535)
						(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
						src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
						dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
						(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
						data_length = len(data_sent) - 37
						byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
						data_recvd = bytes()
						for d in byte_data:
							data_recvd += d

						if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
							if control == ControlType.INIT.value:
								data_recvd = base64.b64decode(data_recvd).decode('utf-8')
								peer_discovery_map[addr[0] + ":" + str(addr[1])] = int(data_recvd)
						success = True
					except socket.timeout:
						pass
			
			# ping both poc and peers
			else:
				for (peer_host, peer_port) in self.peers:
					msg += "," + peer_host + ":" + str(peer_port)
				if self.poc_host != "0":
					msg += "," + self.poc_host + ":" + str(self.poc_port)
					peers_to_ping = [(self.poc_host, self.poc_port)] + list(self.peers)
				else:
					# case in which host doesn't have a PoC
					peers_to_ping = list(self.peers)
				for peer in peers_to_ping:
					success = False
					while not success:
						try:
							data = base64.b64encode(msg.encode('utf-8'))
							packet = Packet(peer[1], self.local_port, socket.gethostbyname(peer[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, data, 0, 0)
							packet.assemble_packet()
							_ = s.sendto(packet.raw, peer)
							data_sent, _ = s.recvfrom(65535)
							(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
							src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
							dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
							(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
							data_length = len(data_sent) - 37
							byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
							data_recvd = bytes()
							for d in byte_data:
								data_recvd += d

							if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
								if control == ControlType.INIT.value:
									data_recvd = base64.b64decode(data_recvd).decode('utf-8')
									peer_discovery_map[peer[0] + ":" + str(peer[1])] = int(data_recvd)
							success = True
						except socket.timeout:
							pass

			time.sleep(0.05)
		s.close()
		return


	# listens to and sends from SERVER_PORT
	def listen(self):
		global listen_thread_alive
		server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server.bind((socket.gethostname(), self.local_port))
		while (listen_thread_alive):
			packet, address = server.recvfrom(BUFFER_SIZE)
			addr = (socket.gethostbyaddr(address[0])[0].split(".")[0], address[1])
			(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", packet)
			src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
			dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
			(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", packet, offset=26)
			data_length = len(packet) - 37
			byte_data = struct.unpack_from("!" + "s" * data_length, packet, offset=-data_length)
			data_recvd = bytes()
			for d in byte_data:
				data_recvd += d

			if verify_ip_checksum(packet) and verify_udp_checksum(packet, data_recvd):
				# both checksums passed; checking UDP checksum may not be necessary at the forwarder level
				if control == ControlType.INIT.value:
					converted_data = base64.b64decode(data_recvd).decode('utf-8')
					length = len(self.peers)
					if "Peer Discovery" in converted_data:
						for peer in converted_data.split("/")[1].split(","):
							host_of_peer = peer.split(":")[0]
							port_of_peer = int(peer.split(":")[1])
							addr_of_peer = (host_of_peer, port_of_peer)
							if addr_of_peer != (self.local_host, self.local_port) and addr_of_peer not in self.peers:
								self.peers.add(addr_of_peer)

						d = base64.b64encode(str(len(self.peers)).encode('utf-8'))
						packet = Packet(addr[1], self.local_port, socket.gethostbyname(addr[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, d, 0, 0)
						packet.assemble_packet()
						server.sendto(packet.raw, addr)
					elif "RTT" in converted_data:
						#server.sendto(data.encode('utf-8'), addr)
						d = base64.b64encode(converted_data.encode('utf-8'))
						packet = Packet(addr[1], self.local_port, socket.gethostbyname(addr[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, d, 0, 0)
						packet.assemble_packet()
						server.sendto(packet.raw, addr)
						host_of_peer = converted_data.split("/")[1].split(":")[0]
						port_of_peer = int(converted_data.split("/")[1].split(":")[1])
						self.roles[(host_of_peer, port_of_peer)] = converted_data.split("/")[2]
					elif "rtt_vectors" in converted_data:
					#server.sendto(data.encode('utf-8'), addr)
						d = base64.b64encode(converted_data.encode('utf-8'))
						packet = Packet(addr[1], self.local_port, socket.gethostbyname(addr[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, d, 0, 0)
						packet.assemble_packet()
						server.sendto(packet.raw, addr)
						from_host = converted_data.split("/")[1].split(":")[0]
						from_port = int(converted_data.split("/")[1].split(":")[1])
						rtt_vectors = converted_data.split("/")[2]
						rtt_vec = {}
						for vector in rtt_vectors.split(","):
							host_port_pair = vector.split("=")
							to_host = host_port_pair[0].split(":")[0]
							to_port = int(host_port_pair[0].split(":")[1])
							rtt = host_port_pair[1]
							rtt_vec[(to_host, to_port)] = float(rtt)
						for (to_host, to_port) in rtt_vec:
							self.rtt_matrix[(from_host, from_port, to_host, to_port)] = rtt_vec[(to_host, to_port)]
					elif "Done with Initialization" in converted_data:
						self.peers_ready.add(addr[0])
						d = base64.b64encode(converted_data.encode('utf-8'))
						packet = Packet(addr[1], self.local_port, socket.gethostbyname(addr[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, d, 0, 0)
						packet.assemble_packet()
						server.sendto(packet.raw, addr)
							
				if control == ControlType.SYN.value:
					# requesting establishment of connection; send back a SYN_ACK
					self.acknowledge_synchronize(src_addr, src_port) # this is where the data came from so send back to this address
				elif control == ControlType.SYN_ACK.value:
					# SYN_ACK means that connection is established from the sender's perspective
					self.acknowledge(src_addr, src_port, 0) # connection is established on sending direction; send back an ACK
					self.conn_send = True
					print("3-way handshake is complete with ", src_addr)
				elif control == ControlType.ACK.value:
					# if conn_established is False, it's an ACK for the SYN_ACK so connection established on receiving direction as well; do nothing
					# else it represents ACK for DATA: if forwarder then move along the packet in the backward direction; if sender, send next fragment of data
					# also if this ACK is for DATA, udp_ack_seq will be > 0
					if udp_ack_seq == 0:
						print("3-way handshake is complete with ", src_addr)
						self.conn_recv = True
					else:
						if self.role == "F":
							if (self.local_host, self.local_port) in self.path:
								index = self.path.index((self.local_host, self.local_port)) 
								self.acknowledge(self.path[index-1][0], self.path[index-1][1], udp_ack_seq)
						elif self.role == "S":
							# send next data fragment
							self.bytes_sent_successfully = udp_ack_seq - self.starting_seq_no
						else:
							# if R, this should only happen during connection establishment which is handled earlier so this shouldn't happen
							print("The Receiver should not have received an ACK. Something is wrong")
		
				elif control == ControlType.DATA.value:
					# if forwarder then move along the packet in forward direction; if receiver, then save data and send back ACK
					if self.role == "F":
						if (self.local_host, self.local_port) in self.path:
							index = self.path.index((self.local_host, self.local_port)) 
							packet = Packet(self.path[index+1][1], self.local_port, socket.gethostbyname(self.path[index+1][0]), socket.gethostbyname(socket.gethostname()), ControlType.DATA, data_recvd, udp_seq, 0)
							self.forward_data(self.path[index+1][0], self.path[index+1][1], packet)
					elif self.role == "R":
						if len(self.last_data_recvd) == 0:
							self.last_data_recvd = data_recvd
							self.data_recvd += data_recvd
							ack_seq_to_send = udp_seq + len(data_recvd)
							self.acknowledge(src_addr, src_port, ack_seq_to_send) # collect the data; use length of total data received as udp_ack_seq
						else:
							# only collect the data if it's not already received
							if self.last_data_recvd  != data_recvd:
								self.last_data_recvd = data_recvd
								self.data_recvd += data_recvd
								ack_seq_to_send = udp_seq + len(data_recvd)
								self.acknowledge(src_addr, src_port, ack_seq_to_send) # collect the data; use length of total data received as udp_ack_seq
						self.acknowledge(src_addr, src_port, ack_seq_to_send)  # or should it be ack_seq_to_send?
					elif self.role == "S":
						# possibly means that the path has been changed to the opposite direction. Therefore, forward data to next Ringo in opposite direction. This should be index+1 if ringo.path is updated.
						print('Looks like one of the Ringos in the optimal path went offline. Changing direction of data transfer')
				elif control == ControlType.NACK.value:
					# used for corrupted data; if forwarder then move along the packet in the backward direction; if sender, send the SAME fragment of data again
					if self.role == "F":
						if (self.local_host, self.local_port) in self.path:
							index = self.path.index((self.local_host, self.local_port)) 
							self.neg_acknowledge(self.path[index-1][0], path[index-1][1])
					elif self.role == "S":
						# RESEND CURRENT DATA FRAGMENT
						self.got_nack = True

				elif control == ControlType.FIN.value:
					# used to end connection; this is an indication to the receiver that the received bytes can now be reconstructed; if forwarder, send along the data
					if self.role == "R":
						print('Finished receiving entire file.')
						self.file_received = base64.b64decode(data_recvd).decode('utf-8')
						index = self.path.index((self.local_host, self.local_port))
						self.acknowledge_fin(self.path[index-1][0], self.path[index-1][1])
						self.assemble_data()
					elif self.role == "F":
						print('received FIN from ', addr[0])
						if (self.local_host, self.local_port) in self.path:
							index = self.path.index((self.local_host, self.local_port))
							self.finish(self.path[index+1][0], self.path[index+1][1], data_recvd)
							print('i am on the optimal path for FIN so sending it to ', self.path[index+1][1])

				elif control == ControlType.ACK_FIN.value:
					if self.role == "S":
						self.fin_sent = True
					elif self.role == "F":
						if (self.local_host, self.local_port) in self.path:
							index = self.path.index((self.local_host, self.local_port)) 
							self.acknowledge_fin(self.path[index-1][0], self.path[index-1][1])

			else:
				# send a NACK packet backwards along the path until received by Sender
				if self.role == "R":
					if control == ControlType.DATA.value:
						index = self.path.index((self.local_host, self.local_port))
						self.neg_acknowledge(self.path[index-1][0], self.path[index-1][1])
				elif self.role == "F" and control == ControlType.DATA.value:
					if (self.local_host, self.local_port) in self.path:
						index = self.path.index((self.local_host, self.local_port))
						self.neg_acknowledge(self.path[index-1][0], self.path[index-1][1])
				else:
					# Sender gets corrupted packet. Assume previous packet not sent correctly.
					self.got_nack = True


	def listen_keep_alive(self):
		global keep_alive_listen_thread_alive
		server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server.bind((socket.gethostname(), self.keep_alive_port))
		while (keep_alive_listen_thread_alive):
			packet, address = server.recvfrom(65535)
			self.acknowledge_keep_alive(address[0], address[1])
			addr = (socket.gethostbyaddr(address[0])[0].split(".")[0], address[1])
			(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", packet)
			src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
			dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
			(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", packet, offset=26)
			data_length = len(packet) - 37
			byte_data = struct.unpack_from("!" + "s" * data_length, packet, offset=-data_length)
			data_recvd = bytes()
			for d in byte_data:
				data_recvd += d

			if verify_ip_checksum(packet) and verify_udp_checksum(packet, data_recvd):
				if control == ControlType.KEEP_ALIVE.value:
					data_recvd = base64.b64decode(data_recvd).decode('utf-8')
					if "###" in data_recvd:
						if not self.peers or not self.rtt_matrix or not self.rtt_vector or not self.roles:
							print('I just woke up. I am updating my peers, peer-roles, RTTs and RTT matrix')
							self.decode_keep_alive_msg(data_recvd)
							self.choose_path()  # get optimal path
					
						peers = data_recvd.split("###")[1].split("/")[1].split("&")
						for peer in peers:
							if peer.split(":")[0] == socket.gethostbyaddr(address[0])[0].split(".")[0]:
								self.active_ringo_map[(socket.gethostbyaddr(address[0])[0].split(".")[0], int(peer.split(":")[1]))] = True


	def initialize_rtt_vector(self):
		for peer in self.peers:
			self.rtt_vector[peer] = float("inf")


	def calculate_rtt_vector(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(2)
		self.initialize_rtt_vector()
		self.roles[(self.local_host, int(self.local_port))] = self.role
		for peer in self.peers:
			counter = 0
			time_diff = 0
			while counter < 4:
				success = False
				while not success:
					try:
						send_time = time.time() * 1000  # time in ms
						msg = "RTT/" + self.local_host + ":" + str(self.local_port) + "/" + self.role
						#_ = s.sendto(msg.encode('utf-8'), peer)

						data = base64.b64encode(msg.encode('utf-8'))
						packet = Packet(peer[1], self.local_port, socket.gethostbyname(peer[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, data, 0, 0)
						packet.assemble_packet()
						_ = s.sendto(packet.raw, peer)
						data_sent, _ = s.recvfrom(65535)
						(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
						src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
						dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
						(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
						data_length = len(data_sent) - 37
						byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
						data_recvd = bytes()
						for d in byte_data:
							data_recvd += d

						if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
							if control == ControlType.INIT.value:
								data_recvd = base64.b64decode(data_recvd).decode('utf-8')
								if data_recvd == msg:
									success = True
									counter += 1 
									recv_time = time.time() * 1000
									time_diff += recv_time - send_time

					except socket.timeout:
						pass
			self.rtt_vector[peer] = time_diff / 4
		pass
		s.close()
		return


	# send to SERVER PORT or create a new port for that?
	def send_rtt_vectors(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(2)
		msg = self.get_rtt_vector_msg()
		self.initialize_rtt_matrix()
		for peer in self.peers:
			success = False
			while not success:
				try:
					time.sleep(0.25)
					data = base64.b64encode(msg.encode('utf-8'))
					packet = Packet(peer[1], self.local_port, socket.gethostbyname(peer[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, data, 0, 0)
					packet.assemble_packet()
					_ = s.sendto(packet.raw, peer)
					data_sent, _ = s.recvfrom(65535)
					(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
					src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
					dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
					(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
					data_length = len(data_sent) - 37
					byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
					data_recvd = bytes()
					for d in byte_data:
						data_recvd += d

					if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
						if control == ControlType.INIT.value:
							data_recvd = base64.b64decode(data_recvd).decode('utf-8')
							if data_recvd == msg:
								success = True

				except socket.timeout:
					pass
		
		s.close()
		while len(self.rtt_matrix) != self.n * self.n:
			time.sleep(0.05)
		print('Done sending RTT vectors')
		return


	def get_rtt_vector_msg(self):
		rtt_vector = self.rtt_vector
		curr_ringo_addr = (socket.gethostname(), self.local_port)
		rtt_vector[curr_ringo_addr] = 0
		msg = "rtt_vectors/" + socket.gethostname() + ":" + str(self.local_port)  + "/"
		for peer in rtt_vector.keys():
			msg += peer[0] + ":" + str(peer[1]) + "=" + str(rtt_vector[peer]) + ","
		if msg:
			msg = msg[:-1]  # remove last comma
		return msg


	def initialize_rtt_matrix(self):
		rtt_vector = self.rtt_vector
		rtt_vector[socket.gethostname(), self.local_port] = 0
		for (host, port) in rtt_vector:
			self.rtt_matrix[(socket.gethostname(), self.local_port, host, port)] = self.rtt_vector[(host, port)]


	def print_rtt_matrix(self):
		all_ringos = [(socket.gethostname(), self.local_port)] + list(self.peers)
		sorted_ringos = sorted(all_ringos)
		print("\nRTT Matrix (in ms)")
		sys.stdout.write("                ")
		for host1, port1 in sorted_ringos:
			sys.stdout.write(" " + host1 + ":" + str(port1))
		sys.stdout.write("\n")
		for from_host, from_port in sorted_ringos:
			sys.stdout.write(from_host + ":" + str(from_port))
			i = 0
			for to_host, to_port in sorted_ringos:
				if i == 0:
					sys.stdout.write("      " + str(round(self.rtt_matrix[(from_host, from_port, to_host, to_port)], 2)) + "      ")
				else:
					sys.stdout.write(str(round(self.rtt_matrix[(from_host, from_port, to_host, to_port)], 2)) + "      ")
			sys.stdout.write("\n")


	def make_rtt_matrix_symmetric(self):
		hosts = [(socket.gethostbyname(socket.gethostname()), self.local_port)] + list(self.peers)
		for host1 in hosts:
			for host2 in hosts:
				rtt1 = self.rtt_matrix[(host1[0], host2[0])]
				rtt2 = self.rtt_matrix[(host2[0], host1[0])]
				average = (rtt1 + rtt2) / 2
				self.rtt_matrix[(host1[0], host2[0])] = average
				self.rtt_matrix[(host2[0], host1[0])] = average


	def optimal_path(self):
		hosts = []
		for peer in self.peers:
			hosts.append(peer[0] + ":" + str(peer[1]))

		possible_orders = list(itertools.permutations([socket.gethostname() + ":" + str(self.local_port)] + hosts +
													  [socket.gethostname() + ":" + str(self.local_port)]))
		sequence_to_rtt = {}
		for order in possible_orders:
			# starting host must be current ringo
			total_rtt = 0
			# rather than having the current ringo as starting point of the optimal path, use sender as starting point
			if order[0] == socket.gethostname() + ":" + str(self.local_port) and order[-1] == socket.gethostname() + ":" + str(self.local_port):
				for i in range(len(order) - 1):
					pair = order[i:i+2]
					from_ringo = pair[0].split(":")
					to_ringo = pair[1].split(":")
					total_rtt += self.rtt_matrix[(from_ringo[0], int(from_ringo[1]), to_ringo[0], int(to_ringo[1]))]
				sequence_to_rtt[order] = total_rtt
		sorted_paths = sorted(sequence_to_rtt.items(), key=operator.itemgetter(1))
		print('Done calculating optimal path')
		return sorted_paths[0][1], sorted_paths[0][0][:-1]   


	# Once ringos get jammed with data packets, the ringos that get lagged behind in RTT calculation won't be able to finish
	# Problem is now tackled with actually handling socket timeouts in sendto blocks. This method might come in handy if problem persists
	def synchronize_initialization(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(2)
		msg = "Done with Initialization"
		while len(self.peers_ready) != self.n-1:
			for peer in self.peers:
				success = False
				while not success:
					try:
						time.sleep(0.5)

						data = base64.b64encode(msg.encode('utf-8'))
						packet = Packet(peer[1], self.local_port, socket.gethostbyname(peer[0]), socket.gethostbyname(socket.gethostname()), ControlType.INIT, data, 0, 0)
						packet.assemble_packet()
						_ = s.sendto(packet.raw, peer)
						data_sent, _ = s.recvfrom(65535)
						(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
						src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
						dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
						(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
						data_length = len(data_sent) - 37
						byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
						data_recvd = bytes()
						for d in byte_data:
							data_recvd += d

						if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
							if control == ControlType.INIT.value:
								data_recvd = base64.b64decode(data_recvd).decode('utf-8')
								if data_recvd == msg:
									success = True
					# handle: try again
					except socket.timeout:
						pass

		s.close()
		while len(self.peers_ready) < self.n-1:
			time.sleep(0.05)
		print('Done with initialization.')
		return

	# This method gives the best path and worst path (to be used when one of the ringos go offline in the best path)
	def establish_path(self):
		_, ring = self.optimal_path()
		path = [(ringo.split(":")[0], int(ringo.split(":")[1])) for ringo in ring]

		for peer in ring:
			addr = peer.split(":")[0]
			port = int(peer.split(":")[1])

		for peer in self.roles:
			# Sender
			if self.roles[peer] == "S":
				sender = peer
			elif self.roles[peer] == "R":
				receiver = peer

		start_pos = path.index(sender)  # should be 0
		end_pos = path.index(receiver)  # anywhere from 1 to N - 1
		clockwise_path = [path[start_pos]]
		# Path 1 (clockwise)
		clockwise_rtt = 0
		if end_pos > start_pos:
			# [F F F S F F F F R]
			for i in range(start_pos, end_pos):
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i+1][0]
				to_ringo_port = path[i+1][1]
				clockwise_path.append(path[i+1])
				clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]
		else:
			# [ F R F F S F F F F F]
			for i in range(start_pos, len(path)-1):
				# covers from S until last position in path
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i+1][0]
				to_ringo_port = path[i+1][1]
				clockwise_path.append(path[i+1])
				clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

			# from last position in path to front of path
			clockwise_path.append(path[0])
			clockwise_rtt += self.rtt_matrix[(path[len(path)-1][0], path[len(path)-1][1], path[0][0], path[0][1])]
			for i in range(0, end_pos):
				# covers from front to R
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i+1][0]
				to_ringo_port = path[i+1][1]
				clockwise_path.append(path[i+1])
				clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

		# Path 2 (counter-clockwise)
		counter_clockwise_path = [path[start_pos]]
		counter_clockwise_rtt = 0
		if end_pos < start_pos:
			# [R F F S F F F F F]
			for i in range(start_pos, end_pos, -1):
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i-1][0]
				to_ringo_port = path[i-1][1]
				counter_clockwise_path.append(path[i-1])
				counter_clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]
		else:
			# [F F F R F F S F F]
			for i in range(start_pos, 0, -1):
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i-1][0]
				to_ringo_port = path[i-1][1]
				counter_clockwise_path.append(path[i-1])
				counter_clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

			# from front to last position in path
			counter_clockwise_path.append(path[len(path) - 1])
			counter_clockwise_rtt += self.rtt_matrix[(path[0][0], path[0][1], path[len(path)-1][0], path[len(path)-1][1])]

			for i in range(len(path) - 1, end_pos, -1):
				from_ringo_addr = path[i][0]
				from_ringo_port = path[i][1]
				to_ringo_addr = path[i-1][0]
				to_ringo_port = path[i-1][1]
				counter_clockwise_path.append(path[i-1])
				counter_clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

		return clockwise_path, clockwise_rtt, counter_clockwise_path, counter_clockwise_rtt


	# choose optimal path based on active ringos
	def choose_path(self):
		while len(self.active_ringos) == 0:
			time.sleep(0.5)   # wait until ringos are active
		
		# self.active_ringos.add((self.local_host, self.local_port))
		# for peer in self.peers:
		#     self.active_ringos.add(peer)  # for now, all ringos are active: remove this

		if (self.local_host, self.local_port) not in self.active_ringos:
			self.active_ringos.add((self.local_host, self.local_port))

		for peer in self.roles:
			if self.roles[peer] == "S":
				sender = peer
			elif self.roles[peer] == "R":
				receiver = peer

		safe_path = []
		safe_path.append(sender)
		safe_path.append(receiver)
		cw_path, cw_rtt, ccw_path, ccw_rtt = self.establish_path()
		# determine optimal path then its validity based on active ringos
		if cw_rtt <= ccw_rtt:
			# clockwise path is optimal
			if set(cw_path).issubset(self.active_ringos):
				self.path = cw_path
				self.data_tx_rtt = cw_rtt
				print('Path chosen: ', self.path)
				return
			elif set(ccw_path).issubset(self.active_ringos):
				self.path = ccw_path
				self.data_tx_rtt = ccw_rtt
				print('Path chosen: ', self.path)
				return
			else:
				self.path = safe_path
				print(self.path)
				return
		else:
			# counter-clockwise path is optimal
			if set(ccw_path).issubset(self.active_ringos):
				self.path = ccw_path
				self.data_tx_rtt = ccw_rtt
				print('Path chosen: ', self.path)
				return

			elif set(cw_path).issubset(self.active_ringos):
				self.path = cw_path
				self.data_tx_rtt = cw_rtt
				print('Path chosen: ', self.path)
				return
			else:
				self.path = safe_path
				print(self.path)
				return

		return


	# 3-way handshake using SYN/ACK packets
	def establish_connection(self):
		print('Establishing connection')
		self.choose_path()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(2)
		if self.path and (self.local_host, self.local_port) in self.path:
			if self.role == "S" or self.role == "F":
				index = self.path.index((self.local_host, self.local_port))
				(dst_addr, dst_port) = self.path[index+1]
				data = base64.b64encode(b'')
				packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.SYN, data, 0, 0)
				packet.assemble_packet()
				# need to keep trying to establish connection until SYNACK received; retry ever 0.1 sec
				while not (self.conn_send):
					success = False
					while not success:
						try:
							time.sleep(0.1)
							_ = s.sendto(packet.raw, (dst_addr, dst_port))
							success = True
						except socket.timeout:
							pass

			if self.role == "F":
				while not self.conn_recv:
					time.sleep(0.05) # wait until connection established on both directions (applicable only to forwarders)

		s.close()
		return


	# send file uploaded by user to receiver; method to only be used by Sender
	def send_file(self, filename):
		with open(filename, "rb") as f:
		   original_data = f.read()
		   encoded_data = base64.b64encode(original_data)

		#encoded_data = base64.b64encode("hey there delilah, how's your day going?".encode('utf-8'))
		# fragment file into approriate sizes. 
		# Implement timeout here based on values from RTT matrix to account for lost packets.
		seq_no = self.starting_seq_no # set to a random number for security
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		send_complete = False
		bytes_sent_attempted = 0
		timeout = self.data_tx_rtt * 3 # take a 300% overhead on timeout based on total RTT from S to R (including hops to/from forwarders)
		# Average of RTT as timeout has proven to be unreliable measure of reality as of now; 
		# maybe do RTT calculations not based on an average of 3 trials but 50 trials?
		for i in range(0, len(encoded_data), DATA_PER_PACKET): # change 3 to len(data)/ for now testing sending first packet
			if i+DATA_PER_PACKET >= len(encoded_data):
				# last packet to be sent
				data_fragment = encoded_data[i:]
			else:
				data_fragment = encoded_data[i:i+DATA_PER_PACKET]

			(dst_addr, dst_port) = self.path[1]  # as sender, it'll always send to the 2nd item in path
			packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.DATA, data_fragment, seq_no, 0)
			packet.assemble_packet()
			send_time = time.time() * 1000  # time in ms
			s.sendto(packet.raw, self.path[1])
			bytes_sent_attempted += len(data_fragment)
			# this handles retransmission of data fragments due to timeout and NACK
			while self.bytes_sent_successfully < bytes_sent_attempted:
				(dst_addr, dst_port) = self.path[1]  # as sender, it'll always send to the 2nd item in path
				packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.DATA, data_fragment, seq_no, 0)
				packet.assemble_packet()
				# this means that we haven't yet hit timeout and haven't received a NACK
				while time.time() * 1000 - send_time < timeout and not self.got_nack:
					if self.bytes_sent_successfully == bytes_sent_attempted:
						break
					time.sleep(0.001) # sleep for 1 ms
					continue
				
				# need to retransmit data
				send_time = time.time() * 1000
				s.sendto(packet.raw, self.path[1])
				if self.got_nack:
					self.got_nack = False # reset NACK received as another attempt is being made to send data

			# if we get here then data fragment is successfully sent
			seq_no += len(data_fragment) # data successfully sent so update sequence number

		s.close()
		print('calling finish')
		self.finish(self.path[1][0], self.path[1][1], base64.b64encode(filename.encode('utf-8'))) # at end of sending the entire file AND receivng an ACK for the last packet, send FIN packet
		return


	def acknowledge_synchronize(self, dst_addr, dst_port):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		data = base64.b64encode(b'')
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.SYN_ACK, data, 0, 0)
		packet.assemble_packet()
		# only send once; if it doesn't go through, the sender needs to keep trying by sending more SYN packets
		success = False
		while not success:
			try:
				time.sleep(0.1)
				_ = s.sendto(packet.raw, (dst_addr, dst_port))
				success = True
			except socket.timeout:
				pass

		s.close()


	def acknowledge(self, dst_addr, dst_port, udp_ack_seq):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		data = base64.b64encode(b'')
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.ACK, data, 0, udp_ack_seq) # dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq=0, udp_ack_seq=0
		packet.assemble_packet()
		# only send once
		success = False
		while not success:
			try:
				time.sleep(0.1)
				_ = s.sendto(packet.raw, (dst_addr, dst_port))
				success = True
			except socket.timeout:
				pass

		s.close()


	def neg_acknowledge(self, dst_addr, dst_port):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		data = base64.b64encode(b'')
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.NACK, data, 0, 0)  #dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq=0, udp_ack_seq=0
		packet.assemble_packet()
		# only send once
		success = False
		while not success:
			try:
				time.sleep(0.1)
				_ = s.sendto(packet.raw, (dst_addr, dst_port))
				success = True
			except socket.timeout:
				pass

		s.close()


	def acknowledge_fin(self, dst_addr, dst_port):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(2)
		data = base64.b64encode(b'')
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.ACK_FIN, data, 0, 0)
		packet.assemble_packet()
		# only send once
		success = False
		while not success:
			print('sending ACK FIN to ', dst_addr)
			try:
				time.sleep(0.1)
				_ = s.sendto(packet.raw, (dst_addr, dst_port))
				success = True
			except socket.timeout:
				pass

		s.close()


	def forward_data(self, dst_addr, dst_port, packet):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		packet.assemble_packet()
		# Implement timeout here for retransmissions to handle lost packets
		success = False
		while not success:
			try:
				time.sleep(0.1)
				_ = s.sendto(packet.raw, (dst_addr, dst_port))
				success = True
			except socket.timeout:
				pass

		s.close()


	def finish(self, dst_addr, dst_port, filename):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		data = filename
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.FIN, data, 0, 0)  #dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq=0, udp_ack_seq=0
		packet.assemble_packet()
		success = False
		while not self.fin_sent:
			timeout = self.data_tx_rtt * 20
			while not success:
				try:
					time.sleep(0.1)
					_ = s.sendto(packet.raw, (dst_addr, dst_port))
					success = True
				except socket.timeout:
					pass
			time.sleep(timeout)

		self.starting_seq_no = random.randint(1, 1000000000)
		self.bytes_sent_successfully = 0   
		self.fin_sent = False
		s.close()
		return


	def assemble_data(self):
		print('Received file ', self.file_received)
		#data_with_padding = "=" * ((4 - len(self.data_recvd) % 4) % 4) # to resolve any padding issues
		try:
			data = base64.b64decode(self.data_recvd)
		except binascii.Error:
			try:
				data = base64.decodebytes(self.data_recvd)
			except:
				data_with_padding = "=" * ((4 - len(self.data_recvd) % 4) % 4)
				data = base64.b64decode(data_with_padding)
			
		# data = base64.b64decode(self.data_recvd)
		# after/before sending FIN, make sure to send the filename along with extension; otherwise it'd be impossible to correctly reconstruct data
		with open(self.file_received, "wb") as f:
		   f.write(data)
		print('Received file ', self.file_received)
		self.data_recvd = bytes()
		self.last_data_recvd = bytes()
		self.file_received = ""
		return


	def keep_alive(self):
		time.sleep(3)
		global keep_alive_ping_thread_alive
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.active_ringos.add((self.local_host, self.local_port))
		for peer in self.peers:
			self.active_ringos.add(peer)

		s.settimeout(2)
		while (keep_alive_ping_thread_alive):
			if len(self.peers) == self.n-1 and len(self.roles) == self.n and len(self.rtt_matrix) == self.n*self.n:
				peers = self.peers
				msg = "Keep Alive###Peers/"
				for peer in self.peers:
					msg += peer[0] + ":" + str(peer[1]) + "&"

				msg += self.local_host + ":" + str(self.local_port)
				msg += "###Roles/"
				for peer in self.roles:
					msg += peer[0] + ":" + str(peer[1]) + "=" + self.roles[peer] + "&"

				msg = msg[:-1]

				msg += "###RTT Matrix/"
				for (from_addr, from_port, to_addr, to_port) in self.rtt_matrix:
					msg += from_addr + ":" + str(from_port) + "," + to_addr + ":" + str(to_port) +  "=" + str(self.rtt_matrix[(from_addr, from_port, to_addr, to_port)]) + "&"

				msg = msg[:-1]
				data = base64.b64encode(msg.encode('utf-8'))
				# packet inputs = dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq, udp_ack_seq
				#msg = base64.b64encode(msg.encode('utf-8'))
				self.active_ringo_map = {}
				self.active_ringo_map[(self.local_host, self.local_port)] = True
				for peer in self.peers:
					# ping each peer continuously for 7.5 seconds. If failed both times then that ringo is offline
					start_time = time.time() # time since packet sent in s
					time_elapsed = 0
					while peer not in self.active_ringo_map and time_elapsed < 12.5:
						# skip if pinging succeeded in first trial
						if peer in self.active_ringo_map:
							continue
						
						(dst_addr, dst_port) = peer
						packet = Packet(self.keep_alive_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.KEEP_ALIVE, data, 0, 0)
						packet.assemble_packet()
						time.sleep(0.25)
						try:
							_ = s.sendto(packet.raw, (dst_addr, self.keep_alive_port))
							data_sent, _ = s.recvfrom(65535)
							(src_addr, dst_addr, _, _, src_port, dst_port) = struct.unpack_from("!LLBBHH", data_sent)
							src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
							dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
							(udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!LLBH", data_sent, offset=26)
							data_length = len(data_sent) - 37
							byte_data = struct.unpack_from("!" + "s" * data_length, data_sent, offset=-data_length)
							data_recvd = bytes()
							for d in byte_data:
								data_recvd += d

							if verify_ip_checksum(data_sent) and verify_udp_checksum(data_sent, data_recvd):
								if control == ControlType.KEEP_ALIVE_ACK.value:
									self.active_ringo_map[peer] = True		
						except socket.timeout:
							pass
						time_elapsed = time.time() - start_time

				time.sleep(1)
				
				if sorted(self.active_ringos) != sorted(set(list(self.active_ringo_map.keys()))):
					self.active_ringos = set(list(self.active_ringo_map.keys()))
					print('One of the Ringos went offline. These are active now: ', self.active_ringos)
					self.choose_path()					


	def acknowledge_keep_alive(self, dst_addr, dst_port):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		data = base64.b64encode(b'')
		packet = Packet(dst_port, self.local_port, socket.gethostbyname(dst_addr), socket.gethostbyname(socket.gethostname()), ControlType.KEEP_ALIVE_ACK, data, 0, 0)
		packet.assemble_packet()
		# only send once
		success = False
		try:
			_ = s.sendto(packet.raw, (dst_addr, dst_port))
		except socket.timeout:
			pass

		s.close()


	def decode_keep_alive_msg(self, msg):
		peers = msg.split("###")[1].split("/")[1].split("&")
		roles = msg.split("###")[2].split("/")[1].split("&")
		rtt_matrix = msg.split("###")[3].split("/")[1].split("&")

		for peer in peers:
			self.peers.add((peer.split(":")[0], int(peer.split(":")[1])))

		for role in roles:
			peer = role.split("=")[0]
			peer_role = role.split("=")[1]
			self.roles[(peer.split(":")[0], int(peer.split(":")[1]))] = peer_role

		for rtt in rtt_matrix:
			peer1 = rtt.split("=")[0].split(",")[0]
			peer2 = rtt.split("=")[0].split(",")[1]
			self.rtt_matrix[(peer1.split(":")[0], int(peer1.split(":")[1]), peer2.split(":")[0], int(peer2.split(":")[1]))] = float(rtt.split("=")[1])

		if (self.local_host, self.local_port) in self.peers:
			self.peers.remove((self.local_host, self.local_port))
		for peer in self.peers:
			self.rtt_vector[peer] = self.rtt_matrix[(self.local_host, self.local_port, peer[0], peer[1])]

		return


def initialize_ringo(flag, local_port, poc_host, poc_port, n):
	ringo.peer_discovery()
	ringo.calculate_rtt_vector()
	ringo.send_rtt_vectors()
	ringo.synchronize_initialization()
	total_rtt, optimal_path = ringo.optimal_path()
	return total_rtt, optimal_path


def thread_sleeper(time_to_sleep):
	time.sleep(time_to_sleep)


# input format: ringo <flag> <local-port> <PoC-name> <PoC-port> <N>

def main():
	global listen_thread_alive
	global keep_alive_listen_thread_alive
	global keep_alive_ping_thread_alive
	global ringo
	listen_thread_alive = True
	keep_alive_listen_thread_alive = True
	keep_alive_ping_thread_alive = True

	if (len(sys.argv) != 6):
		print("Please provide arguments in the form: ringo.py <flag> <local-port> <PoC-name>" +
			  " <PoC-port> <N>")
		return
	print("IP Address: " + socket.gethostbyname(socket.gethostname()))
	print("Host name: " + socket.gethostname())
	flag = sys.argv[1]
	if flag != "S" and flag != "R" and flag != "F":
		print("Flag input must be either S (Sender), R (Receiver) or F (Forwarder)")
		return
	
	local_port = int(sys.argv[2])
	if local_port == 18000:
		print("Please use a port other than 18000, which is being used for Keep Alive.")
		return

	input_poc_host = sys.argv[3]
	poc_host = ""
	if len(input_poc_host.split(".")) == 4:
		poc_host = socket.gethostbyaddr(input_poc_host)[0].split(".")[0]
	else:
		poc_host = input_poc_host

	poc_port = int(sys.argv[4])
	n = int(sys.argv[5])

	ringo = Ringo(flag, local_port, poc_host, poc_port, n)
	
	listen_thread = threading.Thread(target=ringo.listen, args=())
	keep_alive_listen_thread = threading.Thread(target=ringo.listen_keep_alive, args=())
	keep_alive_ping_thread = threading.Thread(target=ringo.keep_alive, args=())

	listen_thread.start()
	total_rtt, optimal_path = initialize_ringo(flag, local_port, poc_host, poc_port, n)
	time.sleep(3)

	keep_alive_listen_thread.start()
	keep_alive_ping_thread.start()
	time.sleep(3) # wait until set of active ringos is populated
	ringo.establish_connection()
	time.sleep(2)
	
	while (1):
		command_input = input("Ringo command: ")
		if command_input == "show-matrix":
			ringo.print_rtt_matrix()
		elif command_input == "show-ring":
			total_rtt, optimal_path = ringo.optimal_path()
			print("\nOptimal Path:")
			print(optimal_path)
			print("\nTotal RTT:")
			print(total_rtt)
		elif "disconnect" in command_input:
			offline_time = int(command_input.split(" ")[1])
			if ringo.role == "S" or ringo.role == "R":
				print(" The Sender and Receiver cannot go offline. Only Forwarders can.")
				continue

			listen_thread_alive = False
			keep_alive_listen_thread_alive = False
			keep_alive_ping_thread_alive = False
			print("Going to sleep for " + str(offline_time) + " seconds.")
			time.sleep(offline_time)
			ringo = Ringo("F", local_port, 0, 0, n)
			listen_thread = threading.Thread(target=ringo.listen, args=())
			keep_alive_listen_thread = threading.Thread(target=ringo.listen_keep_alive, args=())
			keep_alive_ping_thread = threading.Thread(target=ringo.keep_alive, args=())
			listen_thread.start()
			keep_alive_ping_thread.start()
			keep_alive_listen_thread.start()
			print("Ringo is back online now. Listening for Keep Alive messages in order to initialize Ringo")
			keep_alive_listen_thread_alive = True
			while len(ringo.peers) < n-1 or len(ringo.roles) < n or len(ringo.rtt_matrix) < n*n:
				time.sleep(0.05)
			listen_thread_alive = True
			keep_alive_ping_thread_alive = True
			ringo.choose_path()
		elif "send" in command_input:
			filename = command_input.split(" ")[1]
			if flag != "S":
				print("You can only send files from a designated Sender (S); This Ringo is a " + flag)
			else:
				file = Path(filename)
				if file.is_file():
					ringo.send_file(filename)
				else:
					print("The file provided in the prompt doesn't exist.")
				
		else:
			print("Please input one of the follow commands: <show-matrix>, <show-ring>, <disconnect>")

	listen_thread.join()
	keep_alive_ping_thread.join()
	keep_alive_listen_thread.join()

main()
