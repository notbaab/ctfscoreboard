import sqlite3

"""
Container for functions that do database things
"""


def connect_db(db_file, row_factory=sqlite3.Row):
    conn = sqlite3.connect(db_file)
    conn.row_factory = row_factory
    return conn


def update_user_score(conn, user, field, value):
    """Should be in db operations"""
    return execute_trans(conn, "UPDATE USERS set score = (?)", (value,))


def execute_trans(conn, statement, args_tup):
    try:
        cur = conn.cursor()
        print("executing" + statement)
        print(args_tup)
        cur.execute(statement, args_tup)
        conn.commit()
    except Exception as e:
        print(e.message)
        print("fuck man")
        conn.rollback()

    return False


def register_user(conn, username, ip):
    execute_trans(conn, "INSERT INTO users (username,ip) VALUES (?,?)", (username, ip))


def get_all_users(db_con):
    user_query = "SELECT * FROM USERS"
    return query_db(user_query, db_con)

def query_db(query, db, args=(), one=False):
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def user_exists_for_ip(ip):
    users = get_all_users(g.db)
    matching_user = [user for user in users if user["ip"]  == ip]
    return (True if len(matching_user) else False)


def match_user_to_ip(users, ip):
    matching_user = [user for user in users if user["ip"]  == ip]
    return (matching_user[0] if len(matching_user) else None)

