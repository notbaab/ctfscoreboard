from flask import Flask, render_template, request, g, redirect, url_for
from threading import Thread
from argparse import ArgumentParser
from time import sleep
from pprint import pprint
from DbOperations import connect_db, update_user_score, get_all_users

import multiprocessing
import sys
import test_vulns


class AttackCoordinator(object):
    """docstring for AttackCoordinator"""
    def __init__(self, sqlLiteDb, interval=60, starting_delay=1):
        super(AttackCoordinator, self).__init__()
        self.db_file = sqlLiteDb
        self.interval = interval
        self.starting_delay = starting_delay

    def _attack_wrapper(self, attack_fn, timeout, passing_score=1, *args):
        p = multiprocessing.Process(target=attack_fn, args=(args))
        p.start()

        p.join(timeout)

        # If thread is still active
        if p.is_alive():
            print ("Taking too long, killing attack_fn")
            # Terminate
            p.terminate()
            p.join()
            return 0

        # no timeout...do it again? WTF
        if attack_fn(*args):
            return passing_score

        return 0

    def do_attacks(self, ip_addr, attacker):
        # hmmmm...this seems bad
        sys.stdout = open(ip_addr + "attack_log.txt", "a")
        sys.stderr = open(ip_addr + "attack_log_err.txt", "a")
        score = 0

        score += self._attack_wrapper(attacker.test_cmd_injection, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_local_format_string, 1, 1, ip_addr, "chloe", "chloechloe")
        score += self._attack_wrapper(attacker.test_buffer_overflow, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_ssh_jackbauer, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_ssh_chloe, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_ssh_surnow, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_backdoor_1, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_lfi, 1, 1, ip_addr)
        score += self._attack_wrapper(attacker.test_reflected_xss, 1, 1, ip_addr)

        return score

    # accept a list of users that are currently busy processing?
    def perform_attack(self, db_conn, users):

        print("attacking")
        attack_threads = []

        for user in users:
            t = Thread(target=self.preform_attack_user_thread_func, args=(user,))
            t.daemon = True
            t.start()
            attack_threads.append(t)

        return attack_threads

    def preform_attack_user_thread_func(self, user):
        db_conn = connect_db(self.db_file)
        attacker = test_vulns.test_vulns()
        score = self.do_attacks(user["ip"], attacker)
        update_user_score(db_conn, user, "score", score)

    def join_attack_threads(self, threads, timout=1):
        for t in threads:
            t.join()

    def __attack_loop_inner_function__(self):
        db = connect_db(self.db_file)
        users = get_all_users(db)
        attack_threads = self.perform_attack(db, users)
        sleep(self.interval)  # give everything 10 seconds to complete
        self.join_attack_threads(attack_threads)

    def attack_loop(self, starting_delay=1):
        sleep(self.starting_delay)

        while 1:
            self.__attack_loop_inner_function__()


if __name__ == '__main__':
    parser = ArgumentParser(description='Perform attack')
    parser.add_argument('--db-file', default="test.db",
                        help='The database to look for the users')

    args = parser.parse_args()

    attacker = AttackCoordinator(args.db_file)
    attacker.__attack_loop_inner_function__()
