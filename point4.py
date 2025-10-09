# ================================================
# point4.py – Réalisation de découpes en sous-réseaux classiques
# ================================================
# Fonctionnalités :
# - Calcul de découpe classique à partir d'une IP, d'un masque et d'un nombre de SR ou d'IPs/SR
# - Support des modes Classfull et Classless
# - Sauvegarde et chargement des découpes dans la base SQLite existante
# - Attribution d'un responsable (utilisateur connecté)
# - Interface graphique (Tkinter)
# ================================================

import ipaddress
import math
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
        self.current_user = current_user
        self.db = DatabaseManager("users.db")  # Utiliser la même DB que l'authentification

        self.creer_interface()

    # =========================================================
    # Interface graphique
    # =========================================================
    def creer_interface(self):
        """Construit l'interface utilisateur"""
        # Frame principale avec notebook
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill="both")

        # Onglet Nouvelle Découpe
        frame_nouvelle = ttk.Frame(notebook, padding="10")
        self.creer_onglet_nouvelle(frame_nouvelle)
        notebook.add(frame_nouvelle, text="Nouvelle Découpe")

        # Onglet Charger Découpe
        frame_charger = ttk.Frame(notebook, padding="10")
        self.creer_onglet_charger(frame_charger)
        notebook.add(frame_charger, text="Charger Découpe")

        # Zone d'affichage des résultats (commune)
        result_frame = ttk.LabelFrame(main_frame, text="Résultats de la Découpe", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.text_resultats = tk.Text(result_frame, height=15, width=80, font=("Courier", 9))
        scrollbar = ttk.Scrollbar(result_frame, command=self.text_resultats.yview)
        self.text_resultats.configure(yscrollcommand=scrollbar.set)

        self.text_resultats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def creer_onglet_nouvelle(self, parent):
        """Crée l'onglet pour une nouvelle découpe"""
        # Frame de saisie
        input_frame = ttk.LabelFrame(parent, text="Paramètres de Découpe", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Champs de saisie
        ttk.Label(input_frame, text="Nom de la découpe:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_nom = ttk.Entry(input_frame, width=25)
        self.entry_nom.grid(row=0, column=1, pady=5, padx=10)

        ttk.Label(input_frame, text="Adresse IP réseau:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_ip = ttk.Entry(input_frame, width=25)
        self.entry_ip.grid(row=1, column=1, pady=5, padx=10)
        self.entry_ip.insert(0, "192.168.1.0")

        ttk.Label(input_frame, text="Masque:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(input_frame, width=25)
        self.entry_masque.grid(row=2, column=1, pady=5, padx=10)

        # Mode
        self.mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, text="Mode Classless (CIDR) - masque obligatoire",
                        variable=self.mode_var, command=self.changer_mode).grid(row=3, column=0, columnspan=2, pady=5,
                                                                                sticky=tk.W)

        # Aide
        self.label_aide = ttk.Label(input_frame, text="", font=("Arial", 8), foreground="gray")
        self.label_aide.grid(row=4, column=0, columnspan=2, pady=(2, 0), sticky=tk.W)

        # Type de découpe
        self.type_decoupe_var = tk.StringVar(value="nb_sr")
        ttk.Label(input_frame, text="Type de découpe:").grid(row=5, column=0, sticky=tk.W, pady=5)
        ttk.Radiobutton(input_frame, text="Par nombre de SR",
                        variable=self.type_decoupe_var, value="nb_sr",
                        command=self.changer_type_decoupe).grid(row=5, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="Par IPs par SR",
                        variable=self.type_decoupe_var, value="ips_sr",
                        command=self.changer_type_decoupe).grid(row=5, column=2, sticky=tk.W)

        # Champs dynamiques selon le type
        self.frame_dynamique = ttk.Frame(input_frame)
        self.frame_dynamique.grid(row=6, column=0, columnspan=3, sticky=tk.W, pady=5)

        ttk.Label(self.frame_dynamique, text="Nombre de sous-réseaux:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_nb_sr = ttk.Entry(self.frame_dynamique, width=20)
        self.entry_nb_sr.grid(row=0, column=1, pady=5, padx=10)
        self.entry_nb_sr.insert(0, "4")

        ttk.Label(self.frame_dynamique, text="Nombre d'IPs par SR:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_ips_par_sr = ttk.Entry(self.frame_dynamique, width=20)
        self.entry_ips_par_sr.grid(row=1, column=1, pady=5, padx=10)
        self.entry_ips_par_sr.insert(0, "50")

        # Boutons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Calculer la Découpe",
                   command=self.calculer_decoupe).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Sauvegarder",
                   command=self.sauvegarder_decoupe).pack(side=tk.LEFT, padx=5)

        self.changer_mode()
        self.changer_type_decoupe()

    def creer_onglet_charger(self, parent):
        """Crée l'onglet pour charger une découpe existante"""
        input_frame = ttk.LabelFrame(parent, text="Charger une Découpe Existante", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Nom de la découpe:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_nom_charger = ttk.Entry(input_frame, width=25)
        self.entry_nom_charger.grid(row=0, column=1, pady=5, padx=10)

        ttk.Button(input_frame, text="Charger la Découpe",
                   command=self.charger_decoupe).grid(row=1, column=0, columnspan=2, pady=10)

        # Liste des découpes de l'utilisateur
        ttk.Label(input_frame, text="Mes découpes:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.liste_decoupes = tk.Listbox(input_frame, height=6, width=50)
        self.liste_decoupes.grid(row=3, column=0, columnspan=2, pady=5, sticky=tk.W + tk.E)

        ttk.Button(input_frame, text="Actualiser la liste",
                   command=self.actualiser_liste_decoupes).grid(row=4, column=0, columnspan=2, pady=5)

        self.actualiser_liste_decoupes()

    def changer_mode(self):
        """Change l'interface selon le mode"""
        if self.mode_var.get():
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "/24")
            self.label_aide.config(text="Classless: masque obligatoire (ex: /24, 255.255.255.0)")
        else:
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "")
            self.label_aide.config(text="Classful: masque optionnel (si vide, utilise masque de classe)")

    def changer_type_decoupe(self):
        """Affiche les champs appropriés selon le type de découpe"""
        for widget in self.frame_dynamique.winfo_children():
            widget.grid_remove()

        if self.type_decoupe_var.get() == "nb_sr":
            ttk.Label(self.frame_dynamique, text="Nombre de sous-réseaux:").grid(row=0, column=0, sticky=tk.W, pady=5)
            self.entry_nb_sr.grid(row=0, column=1, pady=5, padx=10)
            self.entry_ips_par_sr.grid_remove()
        else:
            ttk.Label(self.frame_dynamique, text="Nombre d'IPs par SR:").grid(row=0, column=0, sticky=tk.W, pady=5)
            self.entry_ips_par_sr.grid(row=0, column=1, pady=5, padx=10)
            self.entry_nb_sr.grid_remove()

    # =========================================================
    # Calcul de découpe
    # =========================================================
    def calculer_decoupe(self):
        """Réalise la découpe classique selon les spécifications"""
        # Récupération des paramètres
        ip = self.entry_ip.get().strip()
        masque_saisi = self.entry_masque.get().strip()
        mode_classless = self.mode_var.get()
        type_decoupe = self.type_decoupe_var.get()

        # Validation de base
        if not ip:
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP")
            return

        try:
            # Validation IP
            ipaddress.IPv4Address(ip)
        except:
            messagebox.showerror("Erreur", "Adresse IP invalide")
            return

        # Validation masque selon le mode
        if mode_classless and not masque_saisi:
            messagebox.showerror("Erreur", "En mode Classless, un masque est obligatoire")
            return

        if not mode_classless and masque_saisi and '/' in masque_saisi:
            messagebox.showerror("Erreur", "En mode Classful, utilisez le format décimal pour le masque")
            return

        # Détermination du réseau selon le mode
        try:
            if mode_classless:
                # MODE CLASSLESS - utilise le masque fourni
                if masque_saisi.startswith('/'):
                    reseau = ipaddress.IPv4Network(f"{ip}{masque_saisi}", strict=False)
                else:
                    reseau = ipaddress.IPv4Network(f"{ip}/{masque_saisi}", strict=False)
            else:
                # MODE CLASSFUL - déduit le masque si non fourni
                if masque_saisi:
                    # Masque fourni en décimal
                    reseau = ipaddress.IPv4Network(f"{ip}/{masque_saisi}", strict=False)
                else:
                    # Pas de masque → déduction automatique
                    premier_octet = int(ip.split('.')[0])
                    if premier_octet <= 127:
                        prefix_classe = 8
                    elif premier_octet <= 191:
                        prefix_classe = 16
                    else:
                        prefix_classe = 24
                    reseau = ipaddress.IPv4Network(f"{ip}/{prefix_classe}", strict=False)
                    masque_saisi = "Déduit"

        except Exception as e:
            messagebox.showerror("Erreur", f"Réseau invalide: {str(e)}")
            return

        # Calcul de la découpe selon le type
        try:
            if type_decoupe == "nb_sr":
                nb_sr = int(self.entry_nb_sr.get().strip())
                if nb_sr <= 0:
                    raise ValueError("Le nombre de SR doit être positif")

                # Calcul du nouveau préfixe
                bits_necessaires = math.ceil(math.log2(nb_sr))
                nouveau_prefix = reseau.prefixlen + bits_necessaires

                if nouveau_prefix > 30:
                    raise ValueError("Trop de sous-réseaux demandés pour le masque actuel")

                sous_reseaux = list(reseau.subnets(new_prefix=nouveau_prefix))
                sous_reseaux = sous_reseaux[:nb_sr]  # On prend seulement le nombre demandé

            else:  # ips_sr
                ips_par_sr = int(self.entry_ips_par_sr.get().strip())
                if ips_par_sr <= 0:
                    raise ValueError("Le nombre d'IPs par SR doit être positif")

                # Calcul du nombre d'IPs nécessaires (inclut réseau et broadcast)
                ips_necessaires = ips_par_sr + 2

                # Trouver le plus petit masque qui peut contenir ce nombre d'IPs
                for bits_hotes in range(2, 30):  # Au moins 2 bits pour hôtes
                    if (2 ** bits_hotes) >= ips_necessaires:
                        nouveau_prefix = 32 - bits_hotes
                        break
                else:
                    raise ValueError("Trop d'IPs demandées par SR")

                if nouveau_prefix <= reseau.prefixlen:
                    raise ValueError("Le réseau de base est trop petit pour cette découpe")

                sous_reseaux = list(reseau.subnets(new_prefix=nouveau_prefix))

            # Affichage des résultats
            self.afficher_resultats(reseau, sous_reseaux, mode_classless, masque_saisi, type_decoupe)

            # Stockage pour sauvegarde
            self.derniere_decoupe = {
                'reseau': reseau,
                'sous_reseaux': sous_reseaux,
                'mode': 'classless' if mode_classless else 'classful',
                'masque_saisi': masque_saisi,
                'type_decoupe': type_decoupe,
                'valeur_decoupe': nb_sr if type_decoupe == "nb_sr" else ips_par_sr
            }

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de calcul: {str(e)}")
            return

    def afficher_resultats(self, reseau, sous_reseaux, mode_classless, masque_saisi, type_decoupe):
        """Affiche le plan d'adressage complet"""
        self.text_resultats.delete(1.0, tk.END)

        mode_text = "CLASSLESS (CIDR)" if mode_classless else "CLASSFUL"
        type_text = "Par nombre de SR" if type_decoupe == "nb_sr" else "Par IPs par SR"

        texte = f"""
=== PLAN D'ADRESSAGE - DÉCOUPE EN SOUS-RÉSEAUX ===

INFORMATIONS GÉNÉRALES:
• Réseau de base: {reseau}
• Masque saisi: {masque_saisi}
• Mode: {mode_text}
• Type de découpe: {type_text}
• Nombre de sous-réseaux créés: {len(sous_reseaux)}
• Masque final: /{sous_reseaux[0].prefixlen} ({sous_reseaux[0].netmask})

DÉTAIL DES SOUS-RÉSEAUX:
"""
        for i, sr in enumerate(sous_reseaux):
            if sr.num_addresses > 2:
                premiere_ip = sr.network_address + 1
                derniere_ip = sr.broadcast_address - 1
                nb_hotes = sr.num_addresses - 2
            else:
                premiere_ip = "N/A"
                derniere_ip = "N/A"
                nb_hotes = 0

            texte += f"""
SR{i + 1:02d}:
  • Plage: {sr.network_address} - {sr.broadcast_address}
  • Sous-réseau: {sr.network_address}/{sr.prefixlen}
  • Broadcast: {sr.broadcast_address}
  • Première IP: {premiere_ip}
  • Dernière IP: {derniere_ip}
  • IPs utilisables: {nb_hotes}
  • Masque: {sr.netmask} (/{sr.prefixlen})
"""

        self.text_resultats.insert(1.0, texte)

    # =========================================================
    # Gestion de la base de données
    # =========================================================
    def sauvegarder_decoupe(self):
        """Sauvegarde la découpe actuelle dans la base de données"""
        if not hasattr(self, 'derniere_decoupe'):
            messagebox.showerror("Erreur", "Veuillez d'abord calculer une découpe")
            return

        nom = self.entry_nom.get().strip()
        if not nom:
            messagebox.showerror("Erreur", "Veuillez donner un nom à la découpe")
            return

        try:
            decoupe = self.derniere_decoupe
            nb_sr = len(decoupe['sous_reseaux']) if decoupe['type_decoupe'] == 'nb_sr' else None
            ips_par_sr = decoupe['valeur_decoupe'] if decoupe['type_decoupe'] == 'ips_sr' else None

            success = self.db.sauvegarder_decoupe(
                nom=nom,
                responsable=self.current_user,
                ip_reseau=str(decoupe['reseau'].network_address),
                masque_original=decoupe['masque_saisi'],
                mode=decoupe['mode'],
                nb_sr=nb_sr,
                ips_par_sr=ips_par_sr,
                masque_final=f"/{decoupe['sous_reseaux'][0].prefixlen}"
            )

            if success:
                messagebox.showinfo("Succès", f"Découpe '{nom}' sauvegardée avec succès!")
                self.actualiser_liste_decoupes()
            else:
                messagebox.showerror("Erreur", f"Une découpe avec le nom '{nom}' existe déjà")

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde: {str(e)}")

    def charger_decoupe(self):
        """Charge une découpe existante depuis la base de données"""
        nom = self.entry_nom_charger.get().strip()
        if not nom:
            messagebox.showerror("Erreur", "Veuillez entrer un nom de découpe")
            return

        try:
            decoupe_data = self.db.charger_decoupe(nom, self.current_user)

            if not decoupe_data:
                messagebox.showerror("Erreur",
                                     f"Aucune découpe trouvée ou vous n'êtes pas le responsable")
                return

            # Remplissage des champs dans l'onglet nouvelle découpe
            self.entry_nom.delete(0, tk.END)
            self.entry_nom.insert(0, decoupe_data['nom'])

            self.entry_ip.delete(0, tk.END)
            self.entry_ip.insert(0, decoupe_data['ip_reseau'])

            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, decoupe_data['masque_original'])

            # Configuration du mode
            self.mode_var.set(decoupe_data['mode'] == 'classless')
            self.changer_mode()

            # Configuration du type de découpe
            if decoupe_data['nb_sr'] is not None:
                self.type_decoupe_var.set("nb_sr")
                self.entry_nb_sr.delete(0, tk.END)
                self.entry_nb_sr.insert(0, str(decoupe_data['nb_sr']))
            else:
                self.type_decoupe_var.set("ips_sr")
                self.entry_ips_par_sr.delete(0, tk.END)
                self.entry_ips_par_sr.insert(0, str(decoupe_data['ips_par_sr']))

            self.changer_type_decoupe()

            # Basculer vers l'onglet nouvelle découpe
            notebook = self.parent.winfo_children()[0].winfo_children()[0]  # Accéder au notebook
            notebook.select(0)  # Sélectionner le premier onglet

            messagebox.showinfo("Succès", f"Découpe '{decoupe_data['nom']}' chargée avec succès!")

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chargement: {str(e)}")

    def actualiser_liste_decoupes(self):
        """Actualise la liste des découpes de l'utilisateur"""
        try:
            decoupes = self.db.lister_decoupes_utilisateur(self.current_user)

            self.liste_decoupes.delete(0, tk.END)
            for nom, ip, masque, date in decoupes:
                self.liste_decoupes.insert(tk.END, f"{nom} - {ip}{masque} - {date[:10]}")

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'actualisation: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Test Découpe SR")
    root.geometry("800x600")
    InterfaceDecoupeSR(ttk.Frame(root, padding="10"), "test_user").parent.pack(fill=tk.BOTH, expand=True)
    root.mainloop()
