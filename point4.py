# ================================================
# point4.py – Réalisation de découpes en sous-réseaux classiques
# ================================================
# Fonctionnalités :
# - Calcul de découpe classique à partir d’une IP, d’un masque et d’un nombre de SR ou d’IPs/SR
# - Support des modes Classfull et Classless
# - Sauvegarde et chargement des découpes dans une base SQLite
# - Attribution d’un responsable (utilisateur connecté)
# - Interface graphique (Tkinter)
# ================================================

import sqlite3
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox
from database import DatabaseManager


class InterfaceDecoupeSR:
    def __init__(self, parent_frame, current_user):
        """
        Interface principale pour la gestion des découpes de sous-réseaux.
        :param parent_frame: Frame parente dans le notebook principal
        :param current_user: Nom d'utilisateur connecté (responsable)
        """
        self.parent = parent_frame
        self.current_user = current_user  # nom de l’utilisateur connecté
        self.db = DatabaseManager("decoupes.db")  # base SQLite dédiée aux découpes

        # Initialisation et interface
        self.init_db_decoupes()
        self.creer_interface()

    # =========================================================
    # Base de données
    # =========================================================
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

    # =========================================================
    # Interface graphique
    # =========================================================
    def creer_interface(self):
        """Construit l’interface utilisateur"""
        frame = ttk.Frame(self.parent)
        frame.pack(expand=True, fill="both", padx=10, pady=10)

        ttk.Label(frame, text="Découpe en Sous-Réseaux (classique)", font=("Arial", 14, "bold")).pack(pady=10)

        champs = ttk.Frame(frame)
        champs.pack(pady=10)

        # --- Champs de saisie ---
        ttk.Label(champs, text="Nom de la découpe :").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_nom = ttk.Entry(champs, width=25)
        self.entry_nom.grid(row=0, column=1, pady=5, padx=10)

        ttk.Label(champs, text="Adresse IP réseau :").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_ip = ttk.Entry(champs, width=25)
        self.entry_ip.grid(row=1, column=1, pady=5, padx=10)

        ttk.Label(champs, text="Masque (CIDR ou décimal) :").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(champs, width=25)
        self.entry_masque.grid(row=2, column=1, pady=5, padx=10)

        ttk.Label(champs, text="Nombre de sous-réseaux :").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.entry_nb_sr = ttk.Entry(champs, width=25)
        self.entry_nb_sr.grid(row=3, column=1, pady=5, padx=10)

        ttk.Label(champs, text="OU nombre d'IPs par SR :").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.entry_ips_par_sr = ttk.Entry(champs, width=25)
        self.entry_ips_par_sr.grid(row=4, column=1, pady=5, padx=10)

        # --- Choix du mode ---
        self.mode = tk.StringVar(value="classless")
        ttk.Label(champs, text="Mode de calcul :").grid(row=5, column=0, sticky=tk.W, pady=5)
        ttk.Radiobutton(champs, text="Classless", variable=self.mode, value="classless").grid(row=5, column=1, sticky=tk.W)
        ttk.Radiobutton(champs, text="Classfull", variable=self.mode, value="classfull").grid(row=5, column=2, sticky=tk.W)

        # --- Boutons d’action ---
        ttk.Button(frame, text="Calculer Découpe", command=self.calculer_decoupe).pack(pady=10)
        ttk.Button(frame, text="Sauvegarder Découpe", command=self.sauvegarder_interface).pack(pady=5)

        # --- Zone d’affichage des résultats ---
        self.result_text = tk.Text(frame, height=15, width=80)
        self.result_text.pack(pady=10)

    # =========================================================
    # Calcul de découpe
    # =========================================================
    def calculer_decoupe(self):
        """Réalise la découpe classique et affiche le plan d’adressage"""
        ip = self.entry_ip.get().strip()
        masque = self.entry_masque.get().strip()
        nb_sr = self.entry_nb_sr.get().strip()
        ips_par_sr = self.entry_ips_par_sr.get().strip()
        mode = self.mode.get()

        # ---------------------
        # Étape 1 : création du réseau
        # ---------------------
        try:
            if mode == "classless":
                # --- Mode Classless ---
                if "/" in ip:
                    network = ipaddress.ip_network(ip, strict=False)
                else:
                    network = ipaddress.ip_network(f"{ip}/{masque}", strict=False)
            else:
                # --- Mode Classfull ---
                first_octet = int(ip.split('.')[0])
                if 0 <= first_octet < 128:
                    default_mask = 8
                elif 128 <= first_octet < 192:
                    default_mask = 16
                else:
                    default_mask = 24
                network = ipaddress.ip_network(f"{ip}/{default_mask}", strict=False)
        except Exception as e:
            messagebox.showerror("Erreur", f"Adresse ou masque invalide : {e}")
            return

        # ---------------------
        # Étape 2 : découpe
        # ---------------------
        try:
            if nb_sr:
                nb_sr = int(nb_sr)
                new_prefix = network.prefixlen + (nb_sr - 1).bit_length()
                subnets = list(network.subnets(new_prefix=new_prefix))
            elif ips_par_sr:
                ips_par_sr = int(ips_par_sr)
                # nombre de bits nécessaires pour obtenir ips_par_sr
                needed_bits = (network.num_addresses // ips_par_sr).bit_length() - 1
                new_prefix = network.prefixlen + needed_bits
                subnets = list(network.subnets(new_prefix=new_prefix))
            else:
                messagebox.showerror("Erreur", "Veuillez indiquer un nombre de SR ou un nombre d’IPs par SR.")
                return
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de calcul : {e}")
            return

        # ---------------------
        # Étape 3 : affichage
        # ---------------------
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Réseau de base : {network}\n")
        self.result_text.insert(tk.END, f"Mode utilisé : {mode}\n")
        self.result_text.insert(tk.END, f"Préfixe original : /{network.prefixlen}\n")
        self.result_text.insert(tk.END, f"Nouveau préfixe : /{new_prefix}\n\n")
        self.result_text.insert(tk.END, "Plan d’adressage :\n")

        for i, sn in enumerate(subnets[:nb_sr or len(subnets)]):
            self.result_text.insert(
                tk.END,
                f"SR{i + 1} : {sn.network_address} - {sn.broadcast_address} "
                f"({sn.num_addresses} IPs)\n"
            )

        messagebox.showinfo("Succès", "Découpe calculée avec succès ✅")

    # =========================================================
    # Sauvegarde d’une découpe
    # =========================================================
    def sauvegarder_interface(self):
        """Récupère les valeurs saisies et appelle la fonction de sauvegarde"""
        nom = self.entry_nom.get().strip()
        ip = self.entry_ip.get().strip()
        masque = self.entry_masque.get().strip()
        nb_sr = self.entry_nb_sr.get().strip()
        ips_par_sr = self.entry_ips_par_sr.get().strip()

        if not nom or not ip or not masque:
            messagebox.showerror("Erreur", "Veuillez remplir au moins le nom, l'IP et le masque.")
            return

        nb_sr = int(nb_sr) if nb_sr else None
        ips_par_sr = int(ips_par_sr) if ips_par_sr else None

        self.sauvegarder_decoupe(nom, ip, masque, nb_sr, ips_par_sr)

    def sauvegarder_decoupe(self, nom, ip, masque, nb_sr=None, ips_par_sr=None):
        """Sauvegarde une découpe dans la base SQLite"""
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
            messagebox.showerror("Erreur", f"Impossible de sauvegarder : {e}")

    # =========================================================
    # Chargement d’une découpe existante
    # =========================================================
    def charger_decoupe(self, nom):
        """Charge une découpe enregistrée si l’utilisateur est le responsable"""
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
