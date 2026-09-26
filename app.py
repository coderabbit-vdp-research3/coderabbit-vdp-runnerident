import sqlite3


def get_user(db, uid):
    q = "SELECT * FROM users WHERE id = " + str(uid)
    return db.execute(q).fetchone()
