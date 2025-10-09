#Léa - point 4
import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import math


class InterfaceDecoupeSR:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.creer_interface()

    def calculer_decoupe(self, ip, masque, nb_sr=None, ips_par_sr=None):
        """Calcule les sous-réseaux ou renvoie un message d’erreur"""
        try:
            reseau = ipaddress.IPv4Network(f"{ip}/{masque}", strict=False)

            if nb_sr is not None:
                if nb_sr <= 0:
                    return None, "Le nombre de sous-réseaux doit être > 0."
                bits = math.ceil(math.log2(nb_sr))
                new_prefix = reseau.prefixlen + bits
                if new_prefix > 30:
                    return None, "Impossible : préfixe trop grand (au-delà de /30)."

                sous_reseaux = list(reseau.subnets(new_prefix=new_prefix))
                info = f"Préfixe /{new_prefix} - {len(sous_reseaux)} SR possibles (≥ {nb_sr})"
                return sous_reseaux, info

            elif ips_par_sr is not None:
                if ips_par_sr < 0:
                    return None, "Le nombre d’IPs par SR doit être ≥ 0."
                hbits = math.ceil(math.log2(ips_par_sr + 2)) if ips_par_sr > 0 else 1
                new_prefix = 32 - hbits
                if new_prefix < reseau.prefixlen:
                    return None, "SR plus grands que le réseau de base."
                if new_prefix > 30:
                    return None, "Impossible : SR trop petits (au-delà de /30)."

                sous_reseaux = list(reseau.subnets(new_prefix=new_prefix))
                info = f"Préfixe /{new_prefix} - {len(sous_reseaux)} SR possibles (≥ {ips_par_sr} IPs/SR)"
                return sous_reseaux, info

            else:
                return None, "Veuillez saisir un critère (nb SR ou nb IPs/SR)."

        except Exception as e:
            return None, f"Erreur : {e}"

    def generer_plan(self):
        """Effectue la découpe et remplit le tableau"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        ip = self.entry_ip.get().strip()
        masque = self.entry_masque.get().strip()
        critere = self.choix.get()
        nb_sr = self.entry_sr.get().strip()
        ips_sr = self.entry_ips.get().strip()

        nb_sr = int(nb_sr) if critere == "sr" and nb_sr else None
        ips_sr = int(ips_sr) if critere == "ips" and ips_sr else None

        sous_reseaux, info = self.calculer_decoupe(ip, masque, nb_sr, ips_sr)

        if not sous_reseaux:
            messagebox.showerror("Erreur", info)
            return

        self.label_info.config(text=info)

        for i, sr in enumerate(sous_reseaux, start=1):
            hosts = list(sr.hosts())
            premiere = hosts[0] if hosts else "-"
            derniere = hosts[-1] if hosts else "-"
            self.tree.insert("", "end", values=(i, str(sr), premiere, derniere, sr.broadcast_address))

    def creer_interface(self):
        """Construit l’interface graphique"""
        frame = tk.LabelFrame(self.parent, text="Paramètres", padx=10, pady=10)
        frame.pack(fill="x", padx=10, pady=10)

        tk.Label(frame, text="Adresse IP :").grid(row=0, column=0, padx=5, pady=5)
        self.entry_ip = tk.Entry(frame)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Masque (/24 ou 255.255.255.0) :").grid(row=0, column=2, padx=5, pady=5)
        self.entry_masque = tk.Entry(frame)
        self.entry_masque.grid(row=0, column=3, padx=5, pady=5)

        self.choix = tk.StringVar(value="sr")
        tk.Radiobutton(frame, text="Nombre de sous-réseaux :", variable=self.choix, value="sr").grid(row=1, column=0, padx=5, pady=5)
        self.entry_sr = tk.Entry(frame)
        self.entry_sr.grid(row=1, column=1, padx=5, pady=5)

        tk.Radiobutton(frame, text="Nombre d’IPs par SR :", variable=self.choix, value="ips").grid(row=1, column=2, padx=5, pady=5)
        self.entry_ips = tk.Entry(frame)
        self.entry_ips.grid(row=1, column=3, padx=5, pady=5)

        tk.Button(frame, text="Générer le plan", command=self.generer_plan).grid(row=2, column=0, columnspan=4, pady=10)

        self.label_info = tk.Label(self.parent, text="", fg="green")
        self.label_info.pack(pady=5)

        colonnes = ("#", "Réseau", "1ère IP", "Dernière IP", "Broadcast")
        self.tree = ttk.Treeview(self.parent, columns=colonnes, show="headings", height=15)
        for col in colonnes:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
