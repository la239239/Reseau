import sqlite3
import bcrypt


class DatabaseManager:
    def __init__(self, db_name="users.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        """Initialise la base de données et crée les tables si elles n'existent pas"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Table des utilisateurs (EXISTANTE - NE PAS MODIFIER)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # NOUVELLE TABLE : découpes de sous-réseaux
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decoupes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT UNIQUE NOT NULL,
                responsable TEXT NOT NULL,
                ip_reseau TEXT NOT NULL,
                masque_original TEXT NOT NULL,
                mode TEXT NOT NULL,
                nb_sr INTEGER,
                ips_par_sr INTEGER,
                masque_final TEXT NOT NULL,
                date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    # =========================================================
    # NOUVELLES MÉTHODES POUR LES DÉCOUPES
    # =========================================================

    def sauvegarder_decoupe(self, nom, responsable, ip_reseau, masque_original, mode, nb_sr, ips_par_sr, masque_final):
        """Sauvegarde une découpe dans la base de données"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO decoupes 
                (nom, responsable, ip_reseau, masque_original, mode, nb_sr, ips_par_sr, masque_final)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (nom, responsable, ip_reseau, masque_original, mode, nb_sr, ips_par_sr, masque_final))

            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False  # Nom de découpe déjà existant
        except Exception as e:
            print(f"Erreur lors de la sauvegarde de la découpe: {e}")
            return False

    def charger_decoupe(self, nom, responsable):
        """Charge une découpe si l'utilisateur est le responsable"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT nom, ip_reseau, masque_original, mode, nb_sr, ips_par_sr, masque_final
                FROM decoupes 
                WHERE nom = ? AND responsable = ?
            ''', (nom, responsable))

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    'nom': result[0],
                    'ip_reseau': result[1],
                    'masque_original': result[2],
                    'mode': result[3],
                    'nb_sr': result[4],
                    'ips_par_sr': result[5],
                    'masque_final': result[6]
                }
            return None
        except Exception as e:
            print(f"Erreur lors du chargement de la découpe: {e}")
            return None

    def lister_decoupes_utilisateur(self, username):
        """Liste toutes les découpes d'un utilisateur"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT nom, ip_reseau, masque_final, date_creation 
                FROM decoupes 
                WHERE responsable = ?
                ORDER BY date_creation DESC
            ''', (username,))

            decoupes = cursor.fetchall()
            conn.close()

            return decoupes
        except Exception as e:
            print(f"Erreur lors de la récupération des découpes: {e}")
            return []

    def supprimer_decoupe(self, nom, responsable):
        """Supprime une découpe si l'utilisateur est le responsable"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM decoupes 
                WHERE nom = ? AND responsable = ?
            ''', (nom, responsable))

            conn.commit()
            conn.close()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Erreur lors de la suppression de la découpe: {e}")
            return False

    def decoupe_existe(self, nom):
        """Vérifie si une découpe existe déjà"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id FROM decoupes WHERE nom = ?
            ''', (nom,))

            result = cursor.fetchone()
            conn.close()

            return result is not None
        except Exception as e:
            print(f"Erreur lors de la vérification: {e}")
            return False
