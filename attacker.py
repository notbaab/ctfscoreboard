from threading import Thread
from argparse import ArgumentParser
from time import sleep
from db_operations import *
from pwn import *

import test_vulns
import sla_check_servers
import requests
import attack_configs


class AttackCoordinator(object):
    """
    The coordinator of the attacks. Resposnible for update database
    based on how the attacks return
    """
    def __init__(self, sql_lite_db, attack_interval=300, starting_delay=1):
        """
        Args:
            sql_lite_db (string): Location of the database
            attack_interval (int, optional): How often you want to attack (if looping)
            starting_delay (int, optional): How long after starting an attack
                                            do you want to wait to start attacking

        """
        super(AttackCoordinator, self).__init__()
        self.db_file = sql_lite_db
        self.attack_interval = attack_interval
        self.starting_delay = starting_delay

    def ping(self, ip, port=80, path=""):
        full_url = 'http://' + ip + ":" + str(port) + "/" + path
        try:
            requests.get(full_url, timeout=5)
            return True
        except requests.exceptions.ConnectTimeout:
            return False
        except Exception:
            return True  # ?

    def score_vulnerability(self, attack_fn, passing_score=1, *args):
        """Summary
            Calls attack_fn and determines what score to give.
            Assumes that attack_fn returns a True if the vulnerable, False if
            fixed or None if the services is unavailable

        Args:
            attack_fn (function): Function to perform attack. Function should be
                                  of signiture
                                  attack_fn(ip, *args) -> (Bool or None)
            passing_score (int, optional): The score to return if the attack
                                           fails
            *args (*args): Arguments to pass to the attack_fn

        Returns:
            Bool or None
        """
        result = attack_fn(*args)

        if not result:
            return passing_score

        if result is None:
            return None

        return 0

    def update_vulnerable_services_table(self, ip, service_name, score, available):
        conn = connect_db(self.db_file)
        # score of 0 indicates vulnerable
        update_vulnerable_services(conn, ip, service_name, score == 0, available)

    def do_attacks(self, ip_addr, attacker, attack_list):
        # hmmmm...this seems bad
        score = 0

        for attack in attack_list:
            available = attack.service_check_func(ip_addr)
            service_score = 0

            if available:
                service_score = self.score_vulnerability(attack.func,
                                                         attack.score,
                                                         ip_addr,
                                                         *attack.args)
                if service_score is None:
                    available = False
                    service_score = 0

            self.update_vulnerable_services_table(ip_addr, attack.name, service_score, available)
            score += service_score

        return score

    def calculate_new_score(self, user, starting_score, attack_list):
        """
        Loop through services list and calculate a new score
        """
        conn = connect_db(self.db_file)
        services = get_all_services(conn, user)

        sum_percentage = 0.0

        for idx, service in enumerate(services):
            sum_percentage += float(service["uptime"]) / (service["downtime"] + service["uptime"])

        average = sum_percentage / len(services)

        return starting_score * average

    # accept a list of users that are currently busy processing?
    def perform_attack(self, db_conn, users):
        attack_threads = {}

        for user in users:
            t = Thread(target=self.preform_attack_user_thread_func, args=(user,))
            t.daemon = True
            t.start()

            attack_threads[user['id']] = t

        return attack_threads

    def preform_attack_user_thread_func(self, user):
        db_conn = connect_db(self.db_file)
        attacker = test_vulns.test_vulns()
        sla_checker = sla_check_servers.sla_check_servers()

        attack_list = attack_configs.get_attack_config_list(attacker, sla_checker)
        score = self.do_attacks(user["ip"], attacker, attack_list)

        weighted_score = self.calculate_new_score(user, score, attack_list)
        update_user_score(db_conn, user, "score", weighted_score)

    def join_attack_threads(self, thread_map, timout=1):
        misbehaving_threads = {}

        for id, t in thread_map.iteritems():
            t.join(1)
            if t.isAlive():
                misbehaving_threads[id] = t

        return misbehaving_threads

    def __attack_loop_inner_function__(self, old_threads):
        db = connect_db(self.db_file)
        users = get_all_users(db)

        user_to_thread_map = self.perform_attack(db, users)
        sleep(self.attack_interval)

        return self.join_attack_threads(user_to_thread_map)

    def attack_loop(self, starting_delay=1):
        sleep(self.starting_delay)

        x = {}
        while 1:
            x = self.__attack_loop_inner_function__(x)

    def perform_attack_on_ip(self, ip):
        db_conn = connect_db(self.db_file)
        user = user_for_ip(db_conn, ip)
        preform_attack_user_thread_func(user)


if __name__ == '__main__':
    parser = ArgumentParser(description='Perform attack')
    parser.add_argument('--db-file', default="data.db",
                        help='The database to look for the users')

    parser.add_argument('--single-ip', help='Perform attack on a single ip')
    parser.add_argument('--loop', help='Perform attack on a single ip', action='store_true')

    args = parser.parse_args()

    attacker = AttackCoordinator(args.db_file)
    if args.single_ip:
        attacker.perform_attack_on_ip(args.single_ip)
    elif args.loop:
	attacker.attack_loop()
    else:
        attacker.__attack_loop_inner_function__({})
