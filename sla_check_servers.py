#!/usr/bin/python

from pwn import *
import requests


class sla_check_servers:
    def ping(self, ip):
        ping = subprocess.Popen(
            ["ping", "-c", "1", "-w", "1", ip], stdout=subprocess.PIPE)
        ping.communicate()
        return ping.returncode == 0

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
            conn.recv()
            conn.send('aaaa\n')
            conn.recv()
        except Exception as e:
            if conn is not None:
                conn.close()
            if type(e) is EOFError:
                return True
        if conn is not None:
            conn.close()
        return False

    def check_cmd_injection(self, ip):
        """
        Check for command injection service on port 2222
        Service should be running in same folder as cmd_injection.py
        @param ip: ip address of target
        """
        conn = None
        try:
            conn = remote(ip, 2222)
            conn.recv()
            conn.send("ls\n")
            if "cmd_injection.py" in conn.recv():
                conn.close()
                return True
        except:
            pass
        if conn is not None:
            conn.close()
        return False

    def check_ssh(self, ip):
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
                conn.close()
                return True
        except:
            pass
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
            if sol0 in results0 and sol1 in results1:
                return True
        except:
            pass
        return False

    def check_local_format_string(self, ip):
        return self.check_ssh(ip)

    def check_reflected_xss(self, ip):
        """
        Check for reflected cross-site scripting (XSS) service
        @param ip: ip address of target
        """
        quote = 'hai_this_is_a_test'
        url = "http://" + ip + "/xss/xss.php?quote=" + quote
        try:
            if quote in wget(url):
                return True
        except:
            pass
        return False

    def check_dom_based_xss(self, ip):
        url = "http://" + ip + "/dom_based_xss/index.html"
        try:
            results = wget(url)
            if '<a href=' in results and 'mission1/' in results:
                return True
        except:
            pass
        return False

    def check_arbitrary_file_upload(self, ip):
        url0 = "http://" + ip + "/arbitrary_file_upload/upload.php"
        url1 = "http://" + ip + "/arbitrary_file_upload/images/"
        file0 = open('assets/file_test.jpg', 'rb')
        files = {'image': file0}
        try:
            requests.post(url0, files=files)
            file0.close()
            if "file_test.jpg" in wget(url1):
                return True
        except:
            pass
        file0.close()
        return False

    def check_sqli(self, ip):
        """
        Check for SQL injection (SQLi)
        @param  ip: ip address of target
        """
        payload = {'codename_input': 'B-Rabbit', 'submitted': 'TRUE'}
        url = "http://" + ip + "/index.php"
        try:
            results = requests.post(url, data=payload)
            if "Codename:</b> B" in results.text and \
                    "Location:</b> Baghdad," in results.text:
                return True
        except:
            pass
        return False

    def dummy_check(self, ip):
        return True

if __name__ == "__main__":
    ip_good = '192.168.3.126'
    ip_bad = '192.168.3.252'
    context.log_level = 'error'
    t = sla_check_servers()

    print t.ping(ip_good)
    print t.check_buffer_overflow(ip_good)
    print t.check_cmd_injection(ip_good)
    print t.check_ssh(ip_good)
    print t.check_lfi(ip_good)
    print t.check_local_format_string(ip_good)
    print t.check_reflected_xss(ip_good)
    print t.check_dom_based_xss(ip_good)
    print t.check_arbitrary_file_upload(ip_good)
    print t.check_sqli(ip_good)

    print False == t.ping(ip_bad)
    print False == t.check_buffer_overflow(ip_bad)
    print False == t.check_cmd_injection(ip_bad)
    print False == t.check_ssh(ip_bad)
    print False == t.check_lfi(ip_bad)
    print False == t.check_local_format_string(ip_bad)
    print False == t.check_reflected_xss(ip_bad)
    print False == t.check_dom_based_xss(ip_bad)
    print False == t.check_arbitrary_file_upload(ip_bad)
    print False == t.check_sqli(ip_bad)
