#! /usr/bin/python

import logging

l=logging.getLogger("scapy.runtime")
l.setLevel(49)

import os,sys,nfqueue,socket
from scapy.all import *

conf.verbose = 0
conf.L3socket = L3RawSocket

def crearPaqueteNuevo(pkt):
    ip = IP()
    udp = UDP()

    ip.src = pkt[IP].src
    ip.dst = pkt[IP].dst
    ip.tos=0
    udp.sport = pkt[UDP].sport
    udp.dport = pkt[UDP].dport

    ip.show()
    send(ip/udp)

def process(i, payload):
    data = payload.get_data()
    pkt = IP(data)
    pkt.show()
    tosAux = pkt.tos
    payload.set_verdict(nfqueue.NF_DROP)
    if tosAux not is 0x00:
		crearPaqueteNuevo(pkt)
		    pass
    elif:
	    print "El paquete no es compatible"
		pass

def main():
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(process)
    q.create_queue(0)

    try:
        q.try_run()
    except KeyboardInterrupt:
        print "Error al crear paquete"
        q.unbind(socket.AF_INET)
        q.close()
        sys.exit(1)


main()
