import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox


class CalculReseau:
    @staticmethod
    def determiner_masque_classe(reseau_ip):
        """Détermine le masque de classe selon le premier octet"""
        premier_octet = int(ipaddress.IPv4Address(reseau_ip).exploded.split('.')[0])
        if premier_octet <= 127:
            return "255.0.0.0", 8, "A"
        elif premier_octet <= 191:
            return "255.255.0.0", 16, "B"
        elif premier_octet <= 223:
            return "255.255.255.0", 24, "C"
        elif premier_octet <= 239:
            return "N/A", 0, "D (Multicast)"
        else:
            return "N/A", 0, "E (Réservée)"

    @staticmethod
    def calculer_infos(ip, masque=None, mode_classless=True):
        try:
            ip = ip.strip()

            if not mode_classless:
                # MODE CLASSFUL - masque optionnel, déduit si non fourni
                masque_classe, prefix_classe, classe_ip = CalculReseau.determiner_masque_classe(ip)

                if masque:
                    # Masque fourni → vérifier format décimal
                    masque = masque.strip()
                    if '/' in masque:
                        raise ValueError("En mode Classful, utilisez le format décimal (ex: 255.255.255.0)")

                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    if '01' in masque_bin:
                        raise ValueError("Masque décimal invalide")

                    # Vérifier si masque = masque de classe
                    masque_egal_classe = (str(masque_obj) == masque_classe)

                    if masque_egal_classe:
                        # Masque = classe → réseau principal
                        reseau = ipaddress.IPv4Network(f"{ip}/{prefix_classe}", strict=False)
                        type_reseau = "Réseau principal (masque de classe)"
                    else:
                        # Masque différent → sous-réseau
                        reseau = ipaddress.IPv4Network(f"{ip}/{masque_obj}", strict=False)
                        reseau_principal = ipaddress.IPv4Network(f"{ip}/{prefix_classe}", strict=False)
                        type_reseau = "Sous-réseau (masque personnalisé)"
                else:
                    # Pas de masque fourni → utiliser masque de classe
                    reseau = ipaddress.IPv4Network(f"{ip}/{prefix_classe}", strict=False)
                    type_reseau = "Réseau principal (masque de classe déduit)"
                    masque_egal_classe = True

            else:
                # MODE CLASSLESS - masque obligatoire
                if not masque:
                    raise ValueError("En mode Classless, vous devez fournir un masque (ex: /24 ou 255.255.255.0)")

                masque = masque.strip()
                if masque.startswith('/'):
                    reseau = ipaddress.IPv4Network(f"{ip}{masque}", strict=False)
                else:
                    masque_obj = ipaddress.IPv4Address(masque)
                    reseau = ipaddress.IPv4Network(f"{ip}/{masque_obj}", strict=False)

                type_reseau = "Réseau CIDR"
                masque_egal_classe = False  # Pas de concept en Classless

            # Préparer le résultat selon le mode
            if not mode_classless:
                if masque_egal_classe or not masque:
                    # Cas 1: Masque = classe ou masque déduit
                    resultat = {
                        'success': True,
                        'mode': 'classful',
                        'masque_egal_classe': True,
                        'classe_ip': classe_ip,
                        'masque_classe': masque_classe,
                        'adresse_reseau': str(reseau.network_address),
                        'adresse_broadcast': str(reseau.broadcast_address),
                        'masque_saisi': masque or "Déduit",
                        'masque_cidr': f"/{reseau.prefixlen}",
                        'masque_decimal': str(reseau.netmask)
                    }
                else:
                    # Cas 2: Masque différent → sous-réseau
                    resultat = {
                        'success': True,
                        'mode': 'classful',
                        'masque_egal_classe': False,
                        'classe_ip': classe_ip,
                        'masque_classe': masque_classe,
                        'adresse_reseau_principal': str(reseau_principal.network_address),
                        'adresse_broadcast_principal': str(reseau_principal.broadcast_address),
                        'adresse_sous_reseau': str(reseau.network_address),
                        'adresse_broadcast_sous_reseau': str(reseau.broadcast_address),
                        'masque_saisi': masque,
                        'masque_cidr': f"/{reseau.prefixlen}",
                        'masque_decimal': str(reseau.netmask)
                    }
            else:
                # MODE CLASSLESS
                resultat = {
                    'success': True,
                    'mode': 'classless',
                    'adresse_sous_reseau': str(reseau.network_address),
                    'adresse_broadcast_sous_reseau': str(reseau.broadcast_address),
                    'masque_saisi': masque,
                    'masque_cidr': f"/{reseau.prefixlen}",
                    'masque_decimal': str(reseau.netmask)
                }

            return resultat

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def valider_masque(masque, mode_classless):
        """Validation stricte selon le mode"""
        try:
            if not masque and not mode_classless:
                return True  # Classful sans masque → OK

            masque = masque.strip()

            if not mode_classless:
                # Classful: format décimal uniquement
                if '/' in masque:
                    return False
                masque_obj = ipaddress.IPv4Address(masque)
                masque_bin = bin(int(masque_obj))[2:].zfill(32)
                return '01' not in masque_bin
            else:
                # Classless: masque obligatoire, accepte CIDR et décimal
                if not masque:
                    return False
                if masque.startswith('/'):
                    prefix = int(masque[1:])
                    return 0 <= prefix <= 32
                else:
                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    return '01' not in masque_bin

        except:
            return False


class InterfaceCalculReseau:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.creer_interface()

    def creer_interface(self):
        """Crée l'interface pour les calculs réseau"""
        # Frame de saisie
        input_frame = ttk.LabelFrame(self.parent, text="Paramètres réseau", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Adresse IP
        ttk.Label(input_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_ip = ttk.Entry(input_frame, width=20)
        self.entry_ip.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.entry_ip.insert(0, "192.168.1.10")

        # Masque
        ttk.Label(input_frame, text="Masque:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(input_frame, width=20)
        self.entry_masque.grid(row=1, column=1, pady=5, padx=(10, 0))

        # Mode
        self.mode_var = tk.BooleanVar(value=True)
        mode_check = ttk.Checkbutton(input_frame, text="Mode Classless (CIDR) - masque obligatoire",
                                     variable=self.mode_var, command=self.changer_mode)
        mode_check.grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.W)

        # Aide
        self.label_aide = ttk.Label(input_frame, text="", font=("Arial", 8), foreground="gray")
        self.label_aide.grid(row=3, column=0, columnspan=2, pady=(2, 0), sticky=tk.W)

        # Bouton calcul
        ttk.Button(input_frame, text="Calculer", command=self.executer_calcul).grid(row=4, column=0, columnspan=2,
                                                                                    pady=10)

        # Frame résultats
        result_frame = ttk.LabelFrame(self.parent, text="Résultats", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        # Zone de texte pour les résultats
        self.text_resultats = tk.Text(result_frame, height=15, width=70, font=("Courier", 9))
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.text_resultats.yview)
        self.text_resultats.configure(yscrollcommand=scrollbar.set)

        self.text_resultats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Initialiser le mode
        self.changer_mode()

    def changer_mode(self):
        """Change l'affichage selon le mode sélectionné"""
        if self.mode_var.get():
            # Mode Classless - CIDR (masque obligatoire)
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "/24")
            self.label_aide.config(text="Classless: masque obligatoire (ex: /24, 255.255.255.0)")
        else:
            # Mode Classful - Décimal (masque optionnel)
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "")
            self.label_aide.config(text="Classful: masque optionnel (si vide, utilise masque de classe)")

    def executer_calcul(self):
        """Exécute les calculs réseau"""
        ip = self.entry_ip.get()
        masque = self.entry_masque.get().strip()
        mode_classless = self.mode_var.get()

        # Validation IP
        if not ip:
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP")
            return

        try:
            ipaddress.IPv4Address(ip.strip())
        except:
            messagebox.showerror("Erreur", "Adresse IP invalide")
            return

        # Validation masque selon le mode
        if not CalculReseau.valider_masque(masque, mode_classless):
            if mode_classless:
                messagebox.showerror("Erreur",
                                     "En mode Classless, un masque valide est obligatoire (ex: /24 ou 255.255.255.0)")
            else:
                messagebox.showerror("Erreur",
                                     "Masque invalide. En Classful, utilisez le format décimal ou laissez vide")
            return

        # Préparer le masque pour le calcul
        masque_calc = masque if masque else None

        # Calcul
        resultat = CalculReseau.calculer_infos(ip, masque_calc, mode_classless)
        self.afficher_resultat(resultat)

    def afficher_resultat(self, resultat):
        """Affiche les résultats formatés"""
        self.text_resultats.delete(1.0, tk.END)

        if not resultat['success']:
            self.text_resultats.insert(1.0, f"❌ ERREUR: {resultat['error']}")
            return

        if resultat['mode'] == 'classful':
            if resultat['masque_egal_classe']:
                # Cas 1: Masque = classe ou masque déduit
                texte = f"""
=== MODE CLASSFUL - RÉSEAU PRINCIPAL ===

Adresse IP: {self.entry_ip.get()}
Masque: {resultat['masque_saisi']} ({resultat['masque_cidr']})
Classe IP: {resultat['classe_ip']}
Masque de classe: {resultat['masque_classe']}

→ RÉSEAU PRINCIPAL :
  • Adresse réseau: {resultat['adresse_reseau']}
  • Adresse broadcast: {resultat['adresse_broadcast']}
  • Masque: {resultat['masque_decimal']} ({resultat['masque_cidr']})

ℹ️ {"Masque correspond au masque de classe" if resultat['masque_saisi'] != "Déduit" else "Masque déduit de la classe"} → pas de sous-réseau
"""
            else:
                # Cas 2: Masque différent → sous-réseau
                texte = f"""
=== MODE CLASSFUL - AVEC SOUS-RÉSEAU ===

Adresse IP: {self.entry_ip.get()}
Masque: {resultat['masque_saisi']} ({resultat['masque_cidr']})
Classe IP: {resultat['classe_ip']}
Masque de classe: {resultat['masque_classe']}

→ RÉSEAU PRINCIPAL :
  • Adresse réseau: {resultat['adresse_reseau_principal']}
  • Adresse broadcast: {resultat['adresse_broadcast_principal']}

→ SOUS-RÉSEAU :
  • Adresse sous-réseau: {resultat['adresse_sous_reseau']}
  • Adresse broadcast: {resultat['adresse_broadcast_sous_reseau']}
  • Masque: {resultat['masque_decimal']} ({resultat['masque_cidr']})

ℹ️ Le masque est différent du masque de classe → création de sous-réseaux
"""
        else:
            # Mode Classless
            masque_affiche = resultat['masque_saisi']
            if not masque_affiche.startswith('/'):
                masque_affiche = f"{resultat['masque_saisi']} ({resultat['masque_cidr']})"

            texte = f"""
=== MODE CLASSLESS (CIDR) ===

Adresse IP: {self.entry_ip.get()}
Masque: {masque_affiche}

→ RÉSEAU :
  • Adresse sous-réseau: {resultat['adresse_sous_reseau']}
  • Adresse broadcast: {resultat['adresse_broadcast_sous_reseau']}
  • Masque: {resultat['masque_decimal']} ({resultat['masque_cidr']})

ℹ️ Mode CIDR - Les classes IP ne sont pas utilisées
"""

        self.text_resultats.insert(1.0, texte)


# Code de test autonome
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Calculateur de Sous-Réseaux - Point 1")
    root.geometry("700x500")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    app = InterfaceCalculReseau(main_frame)
    root.mainloop()
