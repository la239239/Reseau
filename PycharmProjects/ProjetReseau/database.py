import sqlite3
import bcrypt


class DatabaseManager:
    def __init__(self, db_name="users.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        """Initialise la base de données et crée la table si elle n'existe pas"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

    def add_user(self, username, password):
        """Ajoute un nouvel utilisateur avec mot de passe hashé"""
        try:
            # Hashage du mot de passe
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO users (username, password) 
                VALUES (?, ?)
            ''', (username, hashed_password))

            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False  # Nom d'utilisateur déjà existant
        except Exception as e:
            print(f"Erreur lors de l'ajout d'utilisateur: {e}")
            return False

    def verify_user(self, username, password):
        """Vérifie les identifiants de l'utilisateur"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT password FROM users WHERE username = ?
            ''', (username,))

            result = cursor.fetchone()
            conn.close()

            if result:
                stored_password = result[0]
                # Vérification du mot de passe
                return bcrypt.checkpw(password.encode('utf-8'), stored_password)
            return False
        except Exception as e:
            print(f"Erreur lors de la vérification: {e}")
            return False