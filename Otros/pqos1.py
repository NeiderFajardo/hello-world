#!/usr/bin/python
import logging

l=logging.getLogger("scapy.runtime")
l.setLevel(49)

import os,sys,nfqueue,socket
from scapy.all import *

conf.verbose = 0
conf.L3socket = L3RawSocket

#
# def send_echo_reply(pkt):
# 		ip = IP()
# 		icmp = ICMP()
# 		ip.src = pkt[IP].dst
# 		ip.dst = pkt[IP].src
# 		icmp.type = 0
# 		icmp.code = 0
# 		icmp.id = pkt[ICMP].id
# 		icmp.seq = pkt[ICMP].seq
# 		print "Sending back an echo reply to %s" % ip.dst
# 		data = pkt[ICMP].payload
# 		send(ip/icmp/data, verbose=0)


def crearNuevoPaquete(pkt):
	ip = IP()
	udp = UDP()
	ip.src = pkt[IP].src
	ip.dst = pkt[IP].dst
    #ip.tos=32
	udp.sport = pkt[UDP].sport
	udp.dport = pkt[UDP].dport

	solved_ip = "192.168.0.9"
	qd = pkt[UDP].payload
	dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
	dns.qd = qd[DNSQR]
		#dns.an = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
		#dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
		#dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
    #ip.show()
	send(ip/udp/dns)


def process(i, payload):
	data = payload.get_data()
	pkt = IP(data)
    #pkt.show()
	tosAux = pkt.tos


	payload.set_verdict(nfqueue.NF_DROP)
    crearNuevoPaquete(pkt)
    pass
	# if proto is 0x01:
	# 		print "It's an ICMP packet"
	# 		# Idea: intercept an echo request and immediately send back an echo reply packet
	# 		if pkt[ICMP].type is 8:
	# 			print "It's an ICMP echo request packet"
	# 			send_echo_reply(pkt)
	# 		else:
	# 			pass
	# # Check if it is an UDP packet
	# elif proto is 0x11:
	# 	# Check if it is a DNS packet (raw check)
	# 	if pkt[UDP].dport is 53:
	# 		print "It's a DNS request"
	# 		dns = pkt[UDP].payload
	# 		qname = dns[DNSQR].qname
	# 		print "Sir Ping is requesting for %s" % qname
	# 		fake_dns_reply(pkt, qname)
	# else:
	# 	print "Protocol not handled!!"
	# 	pass


def main():
	q = nfqueue.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(process)
	q.create_queue(0)

	try:
		q.try_run()
	except KeyboardInterrupt:
		print "Error al crear el paquete..."
		q.unbind(socket.AF_INET)
		q.close()
		sys.exit(1)

main()
