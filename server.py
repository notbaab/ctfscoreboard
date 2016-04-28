from flask import Flask, render_template, request
from threading import Thread
from argparse import ArgumentParser
from time import sleep

app = Flask(__name__)
attack_interval = 60


def register_user(username, ip, mac):
    return


@app.route("/")
def score():
    return render_template('scoreboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        print("blah")
        return render_template('register.html')
    else:
        print(request.headers)
        register_user("blah", "sd", "lks")


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
