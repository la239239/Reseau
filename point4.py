import sqlite3
from database import DatabaseManager

class InterfaceDecoupeSR:
    def __init__(self, parent_frame, current_user):
        self.parent = parent_frame
        self.current_user = current_user  # username connecté
        self.db = DatabaseManager("decoupes.db")  # nouvelle base pour les découpes
        self.init_db_decoupes()
        self.creer_interface()

    def init_db_decoupes(self):
        """Crée la table des découpes si elle n'existe pas"""
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decoupes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT UNIQUE NOT NULL,
                responsable TEXT NOT NULL,
                ip TEXT NOT NULL,
                masque TEXT NOT NULL,
                nb_sr INTEGER,
                ips_par_sr INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    def sauvegarder_decoupe(self, nom, ip, masque, nb_sr=None, ips_par_sr=None):
        """Sauvegarde une découpe avec le responsable"""
        try:
            conn = sqlite3.connect(self.db.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO decoupes (nom, responsable, ip, masque, nb_sr, ips_par_sr)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nom, self.current_user, ip, masque, nb_sr, ips_par_sr))
            conn.commit()
            conn.close()
            messagebox.showinfo("Succès", f"Découpe '{nom}' enregistrée pour {self.current_user}")
        except sqlite3.IntegrityError:
            messagebox.showerror("Erreur", f"Le nom '{nom}' existe déjà.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de sauvegarder: {e}")

    def charger_decoupe(self, nom):
        """Charge une découpe si l'utilisateur est le responsable"""
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip, masque, nb_sr, ips_par_sr, responsable
            FROM decoupes
            WHERE nom = ?
        ''', (nom,))
        result = cursor.fetchone()
        conn.close()
        if result:
            ip, masque, nb_sr, ips_par_sr, resp = result
            if resp != self.current_user:
                messagebox.showerror("Accès refusé", "Vous n'êtes pas le responsable de cette découpe.")
                return None
            return {"ip": ip, "masque": masque, "nb_sr": nb_sr, "ips_par_sr": ips_par_sr}
        else:
            messagebox.showerror("Erreur", f"Aucune découpe nommée '{nom}' trouvée.")
            return None
