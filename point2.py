import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox


class VerificationIP:
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
    def calculer_infos_reseau(reseau):
        """Calcule toutes les informations d'un réseau"""
        infos = {
            'adresse_reseau': str(reseau.network_address),
            'masque_decimal': str(reseau.netmask),
            'masque_cidr': f"/{reseau.prefixlen}",
            'adresse_broadcast': str(reseau.broadcast_address),
            'nombre_adresses_total': reseau.num_addresses
        }

        # Calculer les IPs machines selon le préfixe
        if reseau.prefixlen == 32:
            infos.update({
                'premiere_ip': "Aucune (adresse unique)",
                'derniere_ip': "Aucune (adresse unique)",
                'nombre_hotes': 0,
                'remarque': "Préfixe /32 = adresse unique (hôte unique)"
            })
        elif reseau.prefixlen == 31:
            infos.update({
                'premiere_ip': "Aucune (lien point-à-point)",
                'derniere_ip': "Aucune (lien point-à-point)",
                'nombre_hotes': reseau.num_addresses,
                'remarque': "Préfixe /31 = lien point-à-point (pas de broadcast)"
            })
        elif reseau.num_addresses > 2:
            infos.update({
                'premiere_ip': str(reseau.network_address + 1),
                'derniere_ip': str(reseau.broadcast_address - 1),
                'nombre_hotes': reseau.num_addresses - 2,
                'remarque': "Réseau standard"
            })
        else:
            infos.update({
                'premiere_ip': "Aucune (réseau trop petit)",
                'derniere_ip': "Aucune (réseau trop petit)",
                'nombre_hotes': 0,
                'remarque': "Réseau sans hôtes utilisables"
            })

        return infos

    @staticmethod
    def verifier_appartenance_ip(ip_a_verifier, reseau_ip, masque_reseau=None, mode_classless=True):
        """Vérifie si une IP appartient à un réseau"""
        try:
            if not mode_classless:
                # MODE CLASSFUL - on devine le masque selon la classe
                masque_classe, prefix_classe, classe_ip = VerificationIP.determiner_masque_classe(reseau_ip)

                if masque_reseau:
                    # Masque fourni → vérifier s'il correspond à la classe
                    masque_obj = ipaddress.IPv4Address(masque_reseau)
                    masque_correspond_classe = (str(masque_obj) == masque_classe)

                    if masque_correspond_classe:
                        # Masque = masque de classe → réseau principal
                        reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                        type_reseau = "Réseau principal (masque de classe)"
                    else:
                        # Masque différent → sous-réseau
                        reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_obj}", strict=False)
                        reseau_principal = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                        type_reseau = "Sous-réseau (masque personnalisé)"
                else:
                    # Pas de masque fourni → utiliser masque de classe
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                    type_reseau = "Réseau principal (masque de classe déduit)"

            else:
                # MODE CLASSLESS - utiliser le masque/prefix fourni obligatoirement
                if not masque_reseau:
                    raise ValueError("En mode Classless, vous devez fournir un masque (ex: /24 ou 255.255.255.0)")

                if masque_reseau.startswith('/'):
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}{masque_reseau}", strict=False)
                else:
                    masque_obj = ipaddress.IPv4Address(masque_reseau)
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_obj}", strict=False)

                type_reseau = "Réseau CIDR"

            # Vérifier appartenance
            ip_verif = ipaddress.IPv4Address(ip_a_verifier)
            appartient = ip_verif in reseau

            # Calculer toutes les infos du réseau
            infos_reseau = VerificationIP.calculer_infos_reseau(reseau)

            resultat = {
                'success': True,
                'appartient': appartient,
                'ip_verifiee': ip_a_verifier,
                'reseau_saisi': reseau_ip,
                'masque_saisi': masque_reseau or "Déduit de la classe",
                'type_reseau': type_reseau,
                **infos_reseau
            }

            # Ajouter infos classe pour Classful
            if not mode_classless:
                resultat['classe_ip'] = classe_ip
                resultat['masque_classe'] = masque_classe
                if 'reseau_principal' in locals():
                    infos_principal = VerificationIP.calculer_infos_reseau(reseau_principal)
                    resultat['reseau_principal'] = infos_principal['adresse_reseau']
                    resultat['broadcast_principal'] = infos_principal['adresse_broadcast']

            return resultat

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def calculer_plage_ip(reseau_ip, masque_reseau=None, mode_classless=True):
        """Calcule uniquement la plage IP machines d'un réseau"""
        try:
            if not mode_classless:
                # MODE CLASSFUL - on devine le masque selon la classe
                masque_classe, prefix_classe, classe_ip = VerificationIP.determiner_masque_classe(reseau_ip)

                if masque_reseau:
                    # Masque fourni → vérifier s'il correspond à la classe
                    masque_obj = ipaddress.IPv4Address(masque_reseau)
                    masque_correspond_classe = (str(masque_obj) == masque_classe)

                    if masque_correspond_classe:
                        # Masque = masque de classe → réseau principal
                        reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                        type_reseau = "Réseau principal (masque de classe)"
                    else:
                        # Masque différent → sous-réseau
                        reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_obj}", strict=False)
                        reseau_principal = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                        type_reseau = "Sous-réseau (masque personnalisé)"
                else:
                    # Pas de masque fourni → utiliser masque de classe
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_classe}", strict=False)
                    type_reseau = "Réseau principal (masque de classe déduit)"

            else:
                # MODE CLASSLESS - utiliser le masque/prefix fourni obligatoirement
                if not masque_reseau:
                    raise ValueError("En mode Classless, vous devez fournir un masque (ex: /24 ou 255.255.255.0)")

                if masque_reseau.startswith('/'):
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}{masque_reseau}", strict=False)
                else:
                    masque_obj = ipaddress.IPv4Address(masque_reseau)
                    reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_obj}", strict=False)

                type_reseau = "Réseau CIDR"

            # Calculer toutes les infos du réseau
            infos_reseau = VerificationIP.calculer_infos_reseau(reseau)

            resultat = {
                'success': True,
                'reseau_saisi': reseau_ip,
                'masque_saisi': masque_reseau or "Déduit de la classe",
                'type_reseau': type_reseau,
                **infos_reseau
            }

            # Ajouter infos classe pour Classful
            if not mode_classless:
                resultat['classe_ip'] = classe_ip
                resultat['masque_classe'] = masque_classe
                if 'reseau_principal' in locals():
                    infos_principal = VerificationIP.calculer_infos_reseau(reseau_principal)
                    resultat['reseau_principal'] = infos_principal['adresse_reseau']
                    resultat['broadcast_principal'] = infos_principal['adresse_broadcast']
                    resultat['premiere_ip_principal'] = infos_principal['premiere_ip']
                    resultat['derniere_ip_principal'] = infos_principal['derniere_ip']
                    resultat['nombre_hotes_principal'] = infos_principal['nombre_hotes']

            return resultat

        except Exception as e:
            return {'success': False, 'error': str(e)}


class InterfaceVerificationIP:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.creer_interface()

    def creer_interface(self):
        """Interface avec deux boutons séparés"""
        # Frame de saisie
        input_frame = ttk.LabelFrame(self.parent, text="Vérification IP et Calcul de Plage", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Champs communs
        ttk.Label(input_frame, text="IP à vérifier:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_ip_verif = ttk.Entry(input_frame, width=20)
        self.entry_ip_verif.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.entry_ip_verif.insert(0, "192.168.1.50")

        ttk.Label(input_frame, text="Réseau:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_reseau = ttk.Entry(input_frame, width=20)
        self.entry_reseau.grid(row=1, column=1, pady=5, padx=(10, 0))
        self.entry_reseau.insert(0, "192.168.1.0")

        ttk.Label(input_frame, text="Masque (optionnel Classful):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(input_frame, width=20)
        self.entry_masque.grid(row=2, column=1, pady=5, padx=(10, 0))

        # Mode
        self.mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, text="Mode Classless (CIDR) - masque obligatoire",
                        variable=self.mode_var, command=self.changer_mode).grid(row=3, column=0, columnspan=2, pady=5,
                                                                                sticky=tk.W)

        # Aide
        self.label_aide = ttk.Label(input_frame, text="", font=("Arial", 8), foreground="gray")
        self.label_aide.grid(row=4, column=0, columnspan=2, pady=(2, 0), sticky=tk.W)

        # DEUX BOUTONS SÉPARÉS
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="🔍 Vérifier Appartenance IP",
                   command=self.verifier_appartenance).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📊 Calculer Plage IP Machines",
                   command=self.calculer_plage).pack(side=tk.LEFT, padx=5)

        # Résultats
        result_frame = ttk.LabelFrame(self.parent, text="Résultats", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.text_resultats = tk.Text(result_frame, height=15, width=70, font=("Courier", 9))
        scrollbar = ttk.Scrollbar(result_frame, command=self.text_resultats.yview)
        self.text_resultats.configure(yscrollcommand=scrollbar.set)

        self.text_resultats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.changer_mode()

    def changer_mode(self):
        """Change l'interface au mode"""
        if self.mode_var.get():
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "/24")
            self.label_aide.config(text="Classless: masque obligatoire (ex: /24, 255.255.255.0)")
        else:
            self.entry_masque.delete(0, tk.END)
            self.entry_masque.insert(0, "")
            self.label_aide.config(text="Classful: masque optionnel (si vide, utilise masque de classe)")

    def valider_saisie_verif(self):
        """Validation pour la vérification d'appartenance"""
        try:
            ip_verif = self.entry_ip_verif.get()
            reseau = self.entry_reseau.get()
            masque = self.entry_masque.get().strip()

            ipaddress.IPv4Address(ip_verif)
            ipaddress.IPv4Address(reseau)

            if self.mode_var.get():
                # Classless: masque obligatoire
                if not masque:
                    return False
                if masque.startswith('/'):
                    prefix = int(masque[1:])
                    if not (0 <= prefix <= 32):
                        return False
                else:
                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    if '01' in masque_bin:
                        return False
            else:
                # Classful: masque optionnel
                if masque and not masque.startswith('/'):
                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    if '01' in masque_bin:
                        return False
                elif masque and masque.startswith('/'):
                    return False

            return True
        except:
            return False

    def valider_saisie_plage(self):
        """Validation pour le calcul de plage"""
        try:
            reseau = self.entry_reseau.get()
            masque = self.entry_masque.get().strip()

            ipaddress.IPv4Address(reseau)

            if self.mode_var.get():
                # Classless: masque obligatoire
                if not masque:
                    return False
                if masque.startswith('/'):
                    prefix = int(masque[1:])
                    if not (0 <= prefix <= 32):
                        return False
                else:
                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    if '01' in masque_bin:
                        return False
            else:
                # Classful: masque optionnel
                if masque and not masque.startswith('/'):
                    masque_obj = ipaddress.IPv4Address(masque)
                    masque_bin = bin(int(masque_obj))[2:].zfill(32)
                    if '01' in masque_bin:
                        return False
                elif masque and masque.startswith('/'):
                    return False

            return True
        except:
            return False

    def verifier_appartenance(self):
        """Vérifie l'appartenance IP"""
        if not self.valider_saisie_verif():
            if self.mode_var.get():
                messagebox.showerror("Erreur", "En mode Classless, un masque valide est obligatoire")
            else:
                messagebox.showerror("Erreur", "Saisie invalide. En Classful, le masque doit être en format décimal")
            return

        masque = self.entry_masque.get().strip()
        if not masque and not self.mode_var.get():
            masque = None

        resultat = VerificationIP.verifier_appartenance_ip(
            self.entry_ip_verif.get(),
            self.entry_reseau.get(),
            masque,
            self.mode_var.get()
        )
        self.afficher_resultat(resultat, "verif")

    def calculer_plage(self):
        """Calcule la plage IP machines"""
        if not self.valider_saisie_plage():
            if self.mode_var.get():
                messagebox.showerror("Erreur", "En mode Classless, un masque valide est obligatoire")
            else:
                messagebox.showerror("Erreur", "Saisie invalide. En Classful, le masque doit être en format décimal")
            return

        masque = self.entry_masque.get().strip()
        if not masque and not self.mode_var.get():
            masque = None

        resultat = VerificationIP.calculer_plage_ip(
            self.entry_reseau.get(),
            masque,
            self.mode_var.get()
        )
        self.afficher_resultat(resultat, "plage")

    def afficher_resultat(self, resultat, type_calcul):
        """Affiche le résultat selon le type de calcul"""
        self.text_resultats.delete(1.0, tk.END)

        if not resultat['success']:
            self.text_resultats.insert(1.0, f"❌ ERREUR: {resultat['error']}")
            return

        if type_calcul == "verif":
            # RÉSULTAT VÉRIFICATION APPARTENANCE
            statut = "✅ APPARTIENT" if resultat['appartient'] else "❌ N'APPARTIENT PAS"

            if not self.mode_var.get():
                # CLASSFUL
                texte = f"""
=== VÉRIFICATION D'APPARTENANCE (Classful) ===

ENTRÉE:
• IP testée: {resultat['ip_verifiee']}
• Réseau demandé: {resultat['reseau_saisi']}
• Masque: {resultat['masque_saisi']}
• Classe IP: {resultat['classe_ip']}
• Masque de classe: {resultat['masque_classe']}

RÉSULTAT PRINCIPAL:
{statut}

DÉTAILS DU RÉSEAU:
• Adresse réseau: {resultat['adresse_reseau']}
• Masque: {resultat['masque_cidr']} ({resultat['masque_decimal']})
• Adresse broadcast: {resultat['adresse_broadcast']}
• Première IP machine: {resultat['premiere_ip']}
• Dernière IP machine: {resultat['derniere_ip']}
• Nombre d'adresses totales: {resultat['nombre_adresses_total']}
• Nombre d'hôtes utilisables: {resultat['nombre_hotes']}

INFORMATIONS SPÉCIALES:
• {resultat['remarque']}
"""
                if 'reseau_principal' in resultat:
                    texte += f"""
--- RÉSEAU PRINCIPAL (Classe {resultat['classe_ip']}) ---
• Adresse réseau: {resultat['reseau_principal']}
• Adresse broadcast: {resultat['broadcast_principal']}
"""
            else:
                # CLASSLESS
                texte = f"""
=== VÉRIFICATION D'APPARTENANCE (Classless) ===

ENTRÉE:
• IP testée: {resultat['ip_verifiee']}
• Réseau demandé: {resultat['reseau_saisi']}
• Masque: {resultat['masque_saisi']}

RÉSULTAT PRINCIPAL:
{statut}

DÉTAILS DU RÉSEAU:
• Adresse réseau: {resultat['adresse_reseau']}
• Masque: {resultat['masque_cidr']} ({resultat['masque_decimal']})
• Adresse broadcast: {resultat['adresse_broadcast']}
• Première IP machine: {resultat['premiere_ip']}
• Dernière IP machine: {resultat['derniere_ip']}
• Nombre d'adresses totales: {resultat['nombre_adresses_total']}
• Nombre d'hôtes utilisables: {resultat['nombre_hotes']}

INFORMATIONS SPÉCIALES:
• {resultat['remarque']}
"""

        else:
            # RÉSULTAT CALCUL PLAGE
            if not self.mode_var.get():
                # CLASSFUL
                texte = f"""
=== PLAGE DES IP MACHINES (Classful) ===

ENTRÉE:
• Réseau demandé: {resultat['reseau_saisi']}
• Masque: {resultat['masque_saisi']}
• Classe IP: {resultat['classe_ip']}
• Masque de classe: {resultat['masque_classe']}

DÉTAILS DU RÉSEAU:
• Adresse réseau: {resultat['adresse_reseau']}
• Masque: {resultat['masque_cidr']} ({resultat['masque_decimal']})
• Adresse broadcast: {resultat['adresse_broadcast']}
• Première IP machine: {resultat['premiere_ip']}
• Dernière IP machine: {resultat['derniere_ip']}
• Nombre d'adresses totales: {resultat['nombre_adresses_total']}
• Nombre d'hôtes utilisables: {resultat['nombre_hotes']}

INFORMATIONS SPÉCIALES:
• {resultat['remarque']}
"""
                if 'reseau_principal' in resultat:
                    texte += f"""
--- RÉSEAU PRINCIPAL (Classe {resultat['classe_ip']}) ---
• Adresse réseau: {resultat['reseau_principal']}
• Adresse broadcast: {resultat['broadcast_principal']}
• Première IP machine: {resultat['premiere_ip_principal']}
• Dernière IP machine: {resultat['derniere_ip_principal']}
• Nombre d'hôtes utilisables: {resultat['nombre_hotes_principal']}
"""
            else:
                # CLASSLESS
                texte = f"""
=== PLAGE DES IP MACHINES (Classless) ===

ENTRÉE:
• Réseau demandé: {resultat['reseau_saisi']}
• Masque: {resultat['masque_saisi']}

DÉTAILS DU RÉSEAU:
• Adresse réseau: {resultat['adresse_reseau']}
• Masque: {resultat['masque_cidr']} ({resultat['masque_decimal']})
• Adresse broadcast: {resultat['adresse_broadcast']}
• Première IP machine: {resultat['premiere_ip']}
• Dernière IP machine: {resultat['derniere_ip']}
• Nombre d'adresses totales: {resultat['nombre_adresses_total']}
• Nombre d'hôtes utilisables: {resultat['nombre_hotes']}

INFORMATIONS SPÉCIALES:
• {resultat['remarque']}
"""

        self.text_resultats.insert(1.0, texte)


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Vérification IP - Point 2")
    root.geometry("750x600")
    InterfaceVerificationIP(ttk.Frame(root, padding="10")).parent.pack(fill=tk.BOTH, expand=True)
    root.mainloop()
    
