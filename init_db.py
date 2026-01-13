import os
import psycopg2
from werkzeug.security import generate_password_hash

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL non définie")

conn = psycopg2.connect(DATABASE_URL, sslmode="require")
cur = conn.cursor()

# Création de la table users
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# Création de l'utilisateur admin
username = "admin"
password = "admin123"  # change-le après la première connexion
password_hash = generate_password_hash(password)

cur.execute("""
INSERT INTO users (username, password_hash, is_admin)
VALUES (%s, %s, TRUE)
ON CONFLICT (username) DO NOTHING;
""", (username, password_hash))

conn.commit()
cur.close()
conn.close()

print("✅ Base initialisée avec succès")
