from enum import Enum
import socket
import struct
import base64


def verify_checksum(msg):
	s = 0

	if (len(msg)%2) == 1:
		msg += struct.pack('!B', 0)

	for i in range(0, len(msg), 2):
		w = (msg[i] << 8) + (msg[i + 1])
		s += w

	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff
	s = s % 65535  # not sure about this; this represents 0xFFFF
	return s == 0


def verify_ip_checksum(packet_ip):
	(src_addr, dst_addr, zeroes, protocol, src_port, dst_port, length, ip_checksum) = struct.unpack_from("!LLBBHHHH", packet_ip)
	ip_fragment = struct.pack('!LLBBHHHH',
		src_addr,
		dst_addr,
		zeroes,
		protocol,
		src_port,
		dst_port,
		length,
		ip_checksum)
	return verify_checksum(ip_fragment)


def verify_udp_checksum(packet_udp, data):
	(src_addr, dst_addr) = struct.unpack_from("!LL", packet_udp)
	(udp_src_port, udp_dst_port, udp_length, udp_checksum, udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!HHHHLLBH", packet_udp, offset=18)
	udp_fragment = struct.pack('!LLHHHLLHBH',
		src_addr,
		dst_addr,
		udp_src_port,
		udp_dst_port,
		udp_length,
		udp_seq,
		udp_ack_seq,
		udp_checksum,
		control,
		data_len)
	udp_fragment += data
	return verify_checksum(udp_fragment)