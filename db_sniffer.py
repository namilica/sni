import sqlite3 as sql
from time import *
from binascii import *
from datetime import datetime

# sniffer table
#	- ts (timestamp)
#	- pid (packet id in network)
#	- type (packet type)
#	- hop_dest
#	- hop_src
#	- path_dest
#	- path_src

class db_sniffer(object):
	def __init__(self):
		i = 0
		ct = str(datetime.now())
		db_name = 'logs/sniffed[' + ct + '].db'
		log_name = 'logs/sniffed[' + ct + '].log'
		print db_name

		self.conn = sql.connect(db_name)
		self.conn.text_factory = str
		self.c = self.conn.cursor()
		self.f = open(log_name, 'w')

		self.c.execute("CREATE TABLE 'sniffer' (ts integer, pts integer, pid integer, type integer, retry integer, hop_dest integer, hop_src integer, path_dest integer, path_src integer)")
		self.c.execute("CREATE TABLE 'acks' (ts integer, pts integer, pid integer, hop_dest integer)")
		self.conn.commit()

	def input_ack(self, network_data):
		query = "INSERT INTO acks (ts, pts, pid, hop_dest) VALUES (" + str(network_data['timestamp']) + ", " + str(network_data['pts']) + ", " + str(network_data['pid']) + ", " + str(network_data['hop_dest']) + ")"
		self.c.execute(query)
		self.conn.commit()


	def input_tx(self, network_data):
		query = "INSERT INTO sniffer (ts, pts, pid, type, hop_dest, hop_src, path_dest, path_src, retry) VALUES (" + str(network_data['timestamp']) + ", " + str(network_data['pts']) + ", " + str(network_data['pid']) + ", " + str(network_data['type']) + ", " + str(network_data['hop_dest']) + ", " + str(network_data['hop_src']) + ", " + str(network_data['path_dest']) + ", " + str(network_data['path_src'])+ ", " + str(network_data['retry'])+ ")"
		self.c.execute(query)
		self.conn.commit()

	def save_raw(self, raw_packet):
		self.f.write(raw_packet + '\n')

	def close(self):
		self.f.close()
		self.conn.close()
