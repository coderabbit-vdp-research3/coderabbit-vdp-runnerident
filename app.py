import sqlite3

# CHECKGATE fixture: deliberately vulnerable sample (authorized CodeRabbit VDP lab)
DEMO_API_TOKEN = "demo-token-NOT-REAL-9f3a"  # hardcoded credential (test fixture)

def get_user(db, uid):
    # SQL injection via string concatenation (deliberate bug)
    q = "SELECT * FROM users WHERE id = " + uid
    return db.execute(q).fetchall()

def clamp_score(x):
    return x  # bug: no clamping applied
