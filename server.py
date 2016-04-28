from flask import Flask, render_template, request, g, redirect, url_for
from threading import Thread
from argparse import ArgumentParser
from time import sleep
from pprint import pprint

import sqlite3
import json


with open('config.json') as data_file:
    config = json.load(data_file)

DATABASE = config['DATABASE']

app = Flask(__name__)
app.config.from_object(__name__)
attack_interval = 60


def connect_db(row_factory):
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = row_factory
    return conn


# boiler plate code form the tutorial
@app.before_request
def before_request():
    g.db = connect_db(sqlite3.Row)


@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


def register_user(username, motto, ip):
    try:
        cur = g.db.cursor()
        cur.execute("INSERT INTO users (ip,mac,score) VALUES (?,?,?)",
                    (ip, username, 0))

        g.db.commit()
        return True
    except:
        g.db.rollback()
        print("fuck man")

    return False


def query_db(query, db, args=(), one=False):
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def get_all_users(db_con):
    user_query = "SELECT * FROM USERS"
    return query_db(user_query, db_con)


def user_exists_for_ip(ip):
    return False


def match_user_to_ip(users, ip):
    matching_user = [user for user in users if user["ip"]  == ip]
    return (matching_user[0] if len(matching_user) else None)


@app.route("/")
def score():
    users = get_all_users(g.db)
    current_user = match_user_to_ip(users, request.remote_addr)

    return render_template('scoreboard.html', users=users, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # redirect to register if already registered
    if user_exists_for_ip(request.remote_addr):
        return redirect(url_for('/'))

    if request.method == 'GET':
        return render_template('register.html')
    else:
        register_user(request.form["username"],
                      request.form["motto"],
                      request.remote_addr)
        return redirect(url_for('score'))


def attack():
    while 1:
        print("attacking")
        sleep(attack_interval)


if __name__ == "__main__":
    parser = ArgumentParser(description='Start the attack server')
    parser.add_argument('--attack-time', default=attack_interval,
                        help='the amount of time in seconds between each attack check')

    parser.add_argument('--prod', action='store_true',
                        help='start server in production mode, i.e. available outside network)')

    args = parser.parse_args()
    attack_interval = attack_interval

    t = Thread(target=attack)

    t.start()
    if args.prod:
        app.run(host='0.0.0.0')
    else:
        app.run(debug=True)
