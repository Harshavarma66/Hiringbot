import sqlite3
def create_leaderboard_table():
    conn = sqlite3.connect("leader.db")
    cursor = conn.cursor()
    # cursor.execute("ALTER TABLE leaderboard ADD COLUMN email TEXT")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS marks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXt,
            technology TEXT,
            score FLOAT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()    
    
def insert_score(name, email, score, tech, timestamp):
    conn = sqlite3.connect("leader.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO marks (name, email,score, technology, timestamp) VALUES (?, ?, ?, ?, ?)",
              (name, email, score, tech, timestamp))
    conn.commit()
    conn.close()   
    
def get_leaderboard(top_n=10):
    conn = sqlite3.connect("leader.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, technology, score, timestamp FROM marks ORDER BY score DESC LIMIT ?", 
                   (top_n,))
    results = cursor.fetchall()
    conn.close()
    return results
