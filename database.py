import sqlite3

def init_db():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS candidates (
            email TEXT PRIMARY KEY,
            name TEXT,
            phone TEXT,
            experience TEXT,
            position TEXT,
            location TEXT
        )
    ''')
    conn.commit()
    conn.close()

def user_exists(email):
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT * FROM candidates WHERE email = ?', (email,))
    result = c.fetchone()
    conn.close()
    return result is not None

def save_user(info):
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO candidates (email, name, phone, location)
        VALUES (?, ?, ?, ?)
    ''', (
        info['Email'], info['Name'], info['Phone'], info['Location']
    ))
    conn.commit()
    conn.close()
