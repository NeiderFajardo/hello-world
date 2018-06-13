#! /usr/bin/python

import logging

l=logging.getLogger("scapy.runtime")
l.setLevel(49)

import os,sys,nfqueue,socket
from scapy.all import *
