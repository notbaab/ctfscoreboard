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
    return execute_trans(conn, "UPDATE USERS set score = (?) where id = (?)", (value,user["id"]))


def execute_trans(conn, statement, args_tup):
    try:
        cur = conn.cursor()
        cur.execute(statement, args_tup)
        conn.commit()
        return True
    except Exception as e:
        print("Rolling back. Transaction " + statement +
              " failed with args " + str(args_tup) + "Error: " + e.message)
        conn.rollback()

    return False


def register_user(conn, username, ip):
    execute_trans(
        conn, "INSERT INTO users (username,ip) VALUES (?,?)", (username, ip))


def get_or_create_vulnerable_service(conn, user, service_name):
    service_query = "SELECT * FROM vulnerable_services WHERE user_id = (?) AND service = (?)"
    service = query_db(
        conn, service_query, args=(user["id"], service_name), one=True)

    if not service:
        insert_query = "INSERT INTO vulnerable_services (user_id, service) VALUES (?,?)"
        success = execute_trans(conn, insert_query, (user["id"], service_name))
        if success:
            service = query_db(
                conn, service_query, args=(user["id"], service_name), one=True)
        else:
            raise ValueError(
                "Can't insert " + service_name + " for user " + str(user))

    return service


def update_vulnerable_services(conn, ip, service_name, vulnerable, is_up):
    user = user_for_ip(conn, ip)
    service = get_or_create_vulnerable_service(conn, user, service_name)
    update_query = "UPDATE vulnerable_services set vulnerable = (?)"
    args = [vulnerable]
    if is_up:
        update_query += ", uptime = (?), available = 1" + str()
        args.append(service["uptime"] + 1)
    else:
        update_query += ", downtime = (?), available = 0"
        args.append(service["downtime"] + 1)

    update_query += " WHERE user_id = (?) AND service = (?)"
    args.append(user["id"])
    args.append(service_name)

    return execute_trans(conn, update_query, args)


def get_all_users(conn):
    user_query = "SELECT * FROM USERS"
    return query_db(conn, user_query)


def get_all_services(conn, user):
    service_query = "SELECT * FROM vulnerable_services WHERE user_id = (?)"
    return query_db(conn, service_query, args=(user["id"],))


def query_db(conn, query, args=(), one=False):
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def user_exists_for_ip(conn, ip):
    users = get_all_users(conn)
    matching_user = [user for user in users if user["ip"] == ip]
    return (True if len(matching_user) else False)


def user_for_ip(conn, ip):
    users = get_all_users(conn)
    matching_user = [user for user in users if user["ip"] == ip]
    return (matching_user[0] if len(matching_user) else None)


def match_user_to_ip(ip, users):
    matching_user = [user for user in users if user["ip"] == ip]
    return (matching_user[0] if len(matching_user) else None)


if __name__ == '__main__':
    # Self test stuff
    print("hello")
    conn = connect_db("self_test.db")
    register_user(conn, "user1", "123.2.2.1")
    register_user(conn, "user2", "123.2.2.2")
    # Add services
    update_vulnerable_services(conn, "123.2.2.1", "service1", True, True)
    update_vulnerable_services(conn, "123.2.2.1", "service2", True, True)
    update_vulnerable_services(conn, "123.2.2.1", "service3", True, False)
    update_vulnerable_services(conn, "123.2.2.2", "service1", True, True)
    update_vulnerable_services(conn, "123.2.2.2", "service2", False, True)
    update_vulnerable_services(conn, "123.2.2.2", "service3", False, True)
