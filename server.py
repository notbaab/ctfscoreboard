from flask import Flask, render_template, request, g, redirect, url_for
from threading import Thread
from argparse import ArgumentParser
from time import sleep
from pprint import pprint
from DbOperations import *

import multiprocessing
import sqlite3
import json
import sys

with open('config.json') as data_file:
    config = json.load(data_file)

DATABASE = config['DATABASE']

app = Flask(__name__)
from attacker import AttackCoordinator # Can't import test_vulns before Flask(__name__)

app.config.from_object(__name__)
attack_interval = 60


# boiler plate code form the tutorial
@app.before_request
def before_request():
    g.db = connect_db(app.config['DATABASE'], sqlite3.Row)


@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


@app.route("/")
def score():
    users = get_all_users(g.db)
    current_user = match_user_to_ip(request.remote_addr, users)

    return render_template('scoreboard.html', users=users, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # redirect to register if already registered
    if user_exists_for_ip(g.db, request.remote_addr):
        return redirect(url_for('score'))

    if request.method == 'GET':
        return render_template('register.html')
    else:
        register_user(g.db,
                      request.form["username"],
                      request.remote_addr)
        return redirect(url_for('score'))


if __name__ == "__main__":
    parser = ArgumentParser(description='Start the attack server')
    parser.add_argument('--attack-interval', default=attack_interval,
                        help='the amount of time in seconds between each attack check')

    parser.add_argument('--prod', action='store_true',
                        help='start server in production mode, i.e. available outside network)')

    parser.add_argument('--no-attack', action='store_true',
                        help="Don't spawn attack thread")

    args = parser.parse_args()

    if not args.no_attack:
        attack_interval = args.attack_interval
        attacker = AttackCoordinator(DATABASE, attack_interval)
        print("Spawning attack thread")
        t = Thread(target=attacker.attack_loop)
        t.daemon = True  # catches ctrl-c interupts
        t.start()

    if args.prod:
        app.run(host='0.0.0.0')
    else:
        app.run(host='0.0.0.0', debug=True)
