import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox


class VerificationIP:
    @staticmethod
    def verifier_appartenance_ip(ip_a_verifier, reseau_ip, masque_reseau):
        """
        Vérifie si une IP appartient à un réseau
        """
        try:
            if '/' in masque_reseau:
                reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_reseau}", strict=False)
            else:
                masque_ip = ipaddress.IPv4Address(masque_reseau)
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{masque_ip}").prefixlen
                reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_len}", strict=False)

            ip_verif = ipaddress.IPv4Address(ip_a_verifier)
            appartient = ip_verif in reseau

            return {
                'success': True,
                'appartient': appartient,
                'ip_verifiee': ip_a_verifier,
                'reseau_cible': str(reseau),
                'premiere_ip_reseau': str(reseau.network_address + 1) if reseau.num_addresses > 2 else str(
                    reseau.network_address),
                'derniere_ip_reseau': str(reseau.broadcast_address - 1) if reseau.num_addresses > 2 else str(
                    reseau.broadcast_address),
                'total_ips': reseau.num_addresses - 2 if reseau.num_addresses > 2 else reseau.num_addresses
            }
        except ValueError as e:
            return {
                'success': False,
                'error': f"Erreur de validation: {str(e)}"
            }

    @staticmethod
    def calculer_plage_ip(reseau_ip, masque_reseau):
        """
        Calcule la plage IP complète d'un réseau
        """
        try:
            if '/' in masque_reseau:
                reseau = ipaddress.IPv4Network(f"{reseau_ip}/{masque_reseau}", strict=False)
            else:
                masque_ip = ipaddress.IPv4Address(masque_reseau)
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{masque_ip}").prefixlen
                reseau = ipaddress.IPv4Network(f"{reseau_ip}/{prefix_len}", strict=False)

            premiere_ip_utilisable = reseau.network_address + 1 if reseau.num_addresses > 2 else reseau.network_address
            derniere_ip_utilisable = reseau.broadcast_address - 1 if reseau.num_addresses > 2 else reseau.broadcast_address

            return {
                'success': True,
                'reseau': str(reseau),
                'adresse_reseau': str(reseau.network_address),
                'adresse_broadcast': str(reseau.broadcast_address),
                'premiere_ip_utilisable': str(premiere_ip_utilisable),
                'derniere_ip_utilisable': str(derniere_ip_utilisable),
                'nombre_ips_utilisables': reseau.num_addresses - 2 if reseau.num_addresses > 2 else reseau.num_addresses
            }
        except ValueError as e:
            return {
                'success': False,
                'error': f"Erreur de calcul: {str(e)}"
            }


class InterfaceVerificationIP:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.creer_interface()

    def creer_interface(self):
        """Crée l'interface pour la vérification d'IP"""
        # Frame de saisie
        input_frame = ttk.LabelFrame(self.parent, text="Vérification d'appartenance", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # IP à vérifier
        ttk.Label(input_frame, text="IP à vérifier:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_ip_verif = ttk.Entry(input_frame, width=20)
        self.entry_ip_verif.grid(row=0, column=1, pady=5, padx=(10, 0))
        self.entry_ip_verif.insert(0, "192.168.1.50")

        # Réseau
        ttk.Label(input_frame, text="Réseau:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_reseau = ttk.Entry(input_frame, width=20)
        self.entry_reseau.grid(row=1, column=1, pady=5, padx=(10, 0))
        self.entry_reseau.insert(0, "192.168.1.0")

        # Masque
        ttk.Label(input_frame, text="Masque:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(input_frame, width=20)
        self.entry_masque.grid(row=2, column=1, pady=5, padx=(10, 0))
        self.entry_masque.insert(0, "24")

        # Boutons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Vérifier appartenance",
                   command=self.verifier_appartenance).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Calculer plage IP",
                   command=self.calculer_plage).pack(side=tk.LEFT, padx=5)

        # Frame résultats
        result_frame = ttk.LabelFrame(self.parent, text="Résultats", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        # Zone de texte pour les résultats
        self.text_resultats = tk.Text(result_frame, height=15, width=60)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.text_resultats.yview)
        self.text_resultats.configure(yscrollcommand=scrollbar.set)

        self.text_resultats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def verifier_appartenance(self):
        """Vérifie l'appartenance d'une IP à un réseau"""
        ip_verif = self.entry_ip_verif.get()
        reseau = self.entry_reseau.get()
        masque = self.entry_masque.get()

        if not self.valider_ip(ip_verif):
            messagebox.showerror("Erreur", "Adresse IP à vérifier invalide")
            return

        if not self.valider_ip(reseau):
            messagebox.showerror("Erreur", "Adresse réseau invalide")
            return

        if not self.valider_masque(masque):
            messagebox.showerror("Erreur", "Masque de sous-réseau invalide")
            return

        resultat = VerificationIP.verifier_appartenance_ip(ip_verif, reseau, masque)

        self.text_resultats.delete(1.0, tk.END)

        if resultat['success']:
            statut = "APPARTIENT" if resultat['appartient'] else "N'APPARTIENT PAS"
            texte_resultat = f"""
=== VÉRIFICATION D'APPARTENANCE ===

IP vérifiée: {resultat['ip_verifiee']}
Réseau cible: {resultat['reseau_cible']}

--- RÉSULTAT ---
L'IP {resultat['ip_verifiee']} {statut} au réseau {resultat['reseau_cible']}

--- PLAGE DU RÉSEAU ---
Première IP utilisable: {resultat['premiere_ip_reseau']}
Dernière IP utilisable: {resultat['derniere_ip_reseau']}
Total d'IPs utilisables: {resultat['total_ips']}
"""
        else:
            texte_resultat = f"ERREUR: {resultat['error']}"

        self.text_resultats.insert(1.0, texte_resultat)

    def calculer_plage(self):
        """Calcule la plage IP d'un réseau"""
        reseau = self.entry_reseau.get()
        masque = self.entry_masque.get()

        if not self.valider_ip(reseau):
            messagebox.showerror("Erreur", "Adresse réseau invalide")
            return

        if not self.valider_masque(masque):
            messagebox.showerror("Erreur", "Masque de sous-réseau invalide")
            return

        resultat = VerificationIP.calculer_plage_ip(reseau, masque)

        self.text_resultats.delete(1.0, tk.END)

        if resultat['success']:
            texte_resultat = f"""
=== PLAGE IP DU RÉSEAU ===

Réseau: {resultat['reseau']}

--- INFORMATIONS ---
Adresse réseau: {resultat['adresse_reseau']}
Adresse broadcast: {resultat['adresse_broadcast']}
Première IP utilisable: {resultat['premiere_ip_utilisable']}
Dernière IP utilisable: {resultat['derniere_ip_utilisable']}
Nombre d'IPs utilisables: {resultat['nombre_ips_utilisables']}
"""
        else:
            texte_resultat = f"ERREUR: {resultat['error']}"

        self.text_resultats.insert(1.0, texte_resultat)

    def valider_ip(self, ip):
        """Valide une adresse IP"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def valider_masque(self, masque):
        """Valide un masque de sous-réseau"""
        try:
            if '/' in masque:
                prefix = int(masque.replace('/', ''))
                return 0 <= prefix <= 32
            else:
                ipaddress.IPv4Address(masque)
                return True
        except (ipaddress.AddressValueError, ValueError):
            return False