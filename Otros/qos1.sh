#!/bin/bash
sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE

#python prueba.py
python icmp_dns_fun.py
