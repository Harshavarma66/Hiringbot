def get_leaderboard(top_n=10):
    conn = sqlite3.connect("leaderboard.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, technology, score, timestamp FROM leaderboard ORDER BY score DESC LIMIT ?", 
                   (top_n,))
    results = cursor.fetchall()
    conn.close()
    return results
