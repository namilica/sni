#!/usr/bin/env python
import socket
import json
import time
from struct import pack, unpack

#SERVER_IP_ADDR = "192.168.11.5"
SERVER_IP_ADDR = "202.92.132.61"
PORT = 5000
BUFFER_SIZE = 1024
GCL="test.ph.edu.upd.resense.node2"

def gdp_log(data, s):
  duata = pack("!QBBBQQQQQ", data["ts"], data["pid"], data["type"], data["retry"], data["path_dest"], data["path_src"], data["hop_dest"], data["hop_src"], data["rssi"])
  message = duata
  a = s.send(message)
  unpacked = unpack("!QBBBQQQQQ", duata)
