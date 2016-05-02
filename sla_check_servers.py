#!/usr/bin/python

from pwn import *

class sla_check_servers:
	client = '';

	def __init__(self, client):
		self.client = client

	def check_buffer_overflow(self, ip):
		"""
		Check for buffer overflow by sending a length limited payload
		The sever should respond with an EOF
		Buffer overflow service is running on port 3333
		@param ip: ip address of target
		"""
		conn = None
		try:
			conn = remote(ip, 3333)
			resp = conn.recv()
			conn.send('aaaa\n')
			conn.recv()
			conn.close()
		except Exception as e:
			if conn is not None:
				conn.close()
			if type(e) is EOFError:
				return True
		return False

	def check_cmd_injection(self, ip):
		"""
		Check for command injection service on port 2222
		Service should be running in same folder as cmd_injection.py
		@param ip: ip address of target
		"""
		conn = None
		results = ''
		try:
			conn = remote(ip, 2222)
			prompt = conn.recv()
			conn.send("ls\n")
			results = conn.recv()
			conn.close()
		except:
			if conn is not None:
				conn.close()
		if "cmd_injection.py" in results:
			return True
		return False

	def check_ssh(self, ip, username, pw):
		"""
		Check for SSH service
		SSH service is running on port 22
		@param ip: ip address of target
		"""
		conn = None
		results = ''
		try:
			conn = remote(ip, 22)
			results = conn.recv()
			if "SSH-2.0-OpenSSH_5.8p1" in results:
				return True
			conn.close()
		except Exception as e:
			if conn is not None:
				conn.close()
		return False

	def check_lfi(self, ip):
		"""
		Check local file inclusion service
		@param ip: ip address of target
		"""
		results0 = ''
		results1 = ''
		url0 = "http://" + ip + "/lfi/lfi.php?language=leetspeek"
		url1 = "http://" + ip + "/lfi/lfi.php?language=urbandictionary"
		sol0 = '1 L3RNZ T0 t4Lk L1k3 d1z wh1l3 pl4y1nG W0W. 4m 1 L33t Y3t?'
		sol1 = 'Porn: The reason most people need a new hard drive'
		try:
			results0 = wget(url0)
			results1 = wget(url1)
			print results0
			print results1
			if sol0 in results0 and sol1 in results1:
				return True
		except:
			return False
		return False

	def check_local_format_string(self, ip, username, pw):
		return check_ssh();

	def check_reflected_xss(self, ip):
		"""
		Check for reflected cross-site scripting (XSS) service
		@param ip: ip address of target
		"""
		quote = 'hai_this_is_a_test'
		url = "http://" + ip + "/xss/xss.php?quote=" + quote
		results = ""
		try:
			if quote in wget(url):
				return True
		except:
			return False
		return False

	def check_dom_based_xss(self, ip):
	def check_arbitrary_file_upload(self, ip):
	def check_sql(self, ip):

if __name__ == "__main__":
	print(sla_test.clients)
	
