import requests, json, time, sys, os, random, traceback, socket, copy
import concurrent.futures, threading
from base64 import b64encode
global current_input, valid_device
current_input = False

if os.name=="nt":
	try:
		import win_unicode_console , colorama
		win_unicode_console.enable()
		colorama.init()
	except:
		G = Y = B = R = W = M = C = end = Bold = underline = ''

# Colors
G, B, R, W, M, C, end, Bold, underline = '\033[32m', '\033[94m', '\033[31m', '\x1b[37m', '\x1b[35m', '\x1b[36m', '\033[0m', "\033[1m", "\033[4m"


threats_classes = []

class threats_checker:
	def __init__(self, packets):
		self.packets   = packets
		self.results   = {}
		self.settings  = {
			"icmp_sweep":{
				"threshold":15
			},
			"arp_sweep":{
				"threshold":25
			}
		}
		self.info = {
			"icmp_sweep":{
				"title":"An attacker attempted to do a ping sweep attack on device(s) on the network!",
				"reference":"https://en.wikipedia.org/wiki/Ping_sweep",
			},
			"arp_sweep":{
				"title":"An attacker attempted to do a arp sweep attack on device(s) on the network!",
				"reference":"https://netscantools.blogspot.com/2009/06/arp-scan-versus-ping-sweep.html",
			}
		}
		self.checkers = [self.icmp_sweep, self.arp_sweep]

	def icmp_sweep(self):
		_name = "icmp_sweep"
		highest_repeat = lambda x:max(set(x), key = x.count)
		echo_packets = []
		for packet in self.packets:
			if "icmp" in packet["protocols"].lower():
				if int(packet.get("ICMPType",10)) in [0,8]: # Echo or echo reply type
					echo_packets.append(packet)
		list_of_src    = [p["srcip"] for p in echo_packets]
		if list_of_src:
			highest_sender = highest_repeat(list_of_src) # The most famous one in the network lol
			if list_of_src.count(highest_sender)<=1:
				highest_sender = None
			if highest_sender:
				if len(echo_packets)>self.settings[_name]["threshold"]:
					return { _name:{ "source":highest_sender, "count":len(echo_packets), "info":self.info[_name] } }
		return None

	def arp_sweep(self):
		_name = "arp_sweep"
		highest_repeat = lambda x:max(set(x), key = x.count)
		arp_packets = []
		for packet in self.packets:
			if "arp" in packet["protocols"].lower():
				if packet["dstmac"].lower()=="ff:ff:ff:ff:ff:ff":
					arp_packets.append(packet)
		list_of_src    = [p["srcmac"] for p in arp_packets]
		if list_of_src:
			highest_sender = highest_repeat(list_of_src) # The most famous one in the network lol
			if list_of_src.count(highest_sender)<=1:
				highest_sender = None
			if highest_sender:
				if len(arp_packets)>self.settings[_name]["threshold"]:
					return { _name:{ "source":highest_sender, "count":len(arp_packets), "info":self.info[_name] } }
		return None

	def helper(self, function):
		return function()

	def launch(self):
		with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
			for result in executor.map(self.helper, self.checkers):
				if result:
					self.results.update(result)
		return self.results
