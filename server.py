from flask import Flask, render_template, request, g, redirect, url_for
from threading import Thread
from argparse import ArgumentParser
from db_operations import *

import sqlite3
import os.path

DATABASE = "data.db"

app = Flask(__name__)

# Can't import pwn tools before Flask(__name__)
from attacker import AttackCoordinator
from pwn import log

app.config.from_object(__name__)
DEFAULT_ATTACK_INTERVAL = 60 * 5
DEFAULT_START_DELAY = 60 * 5  # five minutes


# boiler plate code form the tutorial
@app.before_request
def before_request():
    g.db = connect_db(DATABASE, sqlite3.Row)


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


@app.route('/detailedscoreboard', methods=['GET'])
def details():
    # redirect to register if already registered
    user = user_for_ip(g.db, request.remote_addr)
    if not user:
        return redirect(url_for('score'))

    services = get_all_services(g.db, user)
    return render_template('detailed_scoreboard.html', services=services)


@app.route('/details/<vulnerability>')
def get_vulnerability_details(vulnerability):
    startdir = os.path.abspath(os.curdir)
    vulnerability_details_file = os.path.join(startdir,
                                              "vulnerability_details",
                                              vulnerability + ".txt")

    requested_path = os.path.relpath(vulnerability_details_file, startdir)
    requested_path = os.path.abspath(requested_path)

    if os.path.commonprefix([requested_path, startdir]) != startdir or \
       not os.path.isfile(vulnerability_details_file):
        return redirect(url_for('score'))

    with open(vulnerability_details_file, 'r') as details_file:
        name = details_file.readline()
        details_file.readline()
        summary = details_file.read()

    return render_template('vulnerability_details.html', name=name, details=summary)


if __name__ == "__main__":
    parser = ArgumentParser(description='Start the attack server')
    parser.add_argument('--attack-interval', default=DEFAULT_ATTACK_INTERVAL, type=int,
                        help='the amount of time in seconds between each attack check')

    parser.add_argument('--starting-delay', default=DEFAULT_START_DELAY, type=int,
                        help='the amount of time in seconds between each attack check')

    parser.add_argument('--prod', action='store_true',
                        help='start server in production mode, i.e. available outside network)')

    parser.add_argument('--no-attack', action='store_true',
                        help="Don't spawn attack thread")

    args = parser.parse_args()

    if not args.no_attack:
        attack_interval = args.attack_interval
        starting_delay = args.starting_delay
        attacker = AttackCoordinator(DATABASE,
                                     attack_interval=attack_interval,
                                     starting_delay=starting_delay)
        log.info("Spawning attack thread")
        t = Thread(target=attacker.attack_loop)
        t.daemon = True  # catches ctrl-c interupts
        t.start()

    if args.prod:
        app.run(host='0.0.0.0')
    else:
        app.run(host='0.0.0.0', debug=True)
