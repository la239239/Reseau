import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox


class CalculReseau:
    @staticmethod
    def calculer_infos_reseau(ip, masque, mode_classless=True):
        """
        Calcule les informations réseau à partir d'une IP et d'un masque
        """
        try:
            if mode_classless:
                if '/' in masque:
                    reseau = ipaddress.IPv4Network(f"{ip}/{masque}", strict=False)
                else:
                    masque_ip = ipaddress.IPv4Address(masque)
                    prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{masque_ip}").prefixlen
                    reseau = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
            else:
                reseau = ipaddress.IPv4Network(f"{ip}/{masque}", strict=False)

            return {
                'success': True,
                'adresse_reseau': str(reseau.network_address),
                'masque_cidr': f"/{reseau.prefixlen}",
                'masque_sous_reseau': str(reseau.netmask),
                'adresse_broadcast': str(reseau.broadcast_address),
                'premiere_ip': str(reseau.network_address + 1) if reseau.num_addresses > 2 else "N/A",
                'derniere_ip': str(reseau.broadcast_address - 1) if reseau.num_addresses > 2 else "N/A",
                'nombre_ips': reseau.num_addresses - 2 if reseau.num_addresses > 2 else reseau.num_addresses,
                'classe': CalculReseau.determiner_classe_ip(reseau.network_address)
            }
        except ValueError as e:
            return {
                'success': False,
                'error': f"Adresse IP ou masque invalide: {str(e)}"
            }

    @staticmethod
    def determiner_classe_ip(ip_address):
        """Détermine la classe d'une adresse IP"""
        premier_octet = int(ip_address.exploded.split('.')[0])

        if premier_octet <= 127:
            return "A"
        elif premier_octet <= 191:
            return "B"
        elif premier_octet <= 223:
            return "C"
        elif premier_octet <= 239:
            return "D (Multicast)"
        else:
            return "E (Réservée)"

    @staticmethod
    def valider_ip(ip):
        """Valide une adresse IP"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def valider_masque(masque):
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
        ttk.Label(input_frame, text="Masque (CIDR ou décimal):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_masque = ttk.Entry(input_frame, width=20)
        self.entry_masque.grid(row=1, column=1, pady=5, padx=(10, 0))
        self.entry_masque.insert(0, "24")

        # Mode
        self.mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, text="Mode Classless",
                        variable=self.mode_var).grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.W)

        # Bouton calcul
        ttk.Button(input_frame, text="Calculer", command=self.executer_calcul).grid(row=3, column=0, columnspan=2,
                                                                                    pady=10)

        # Frame résultats
        result_frame = ttk.LabelFrame(self.parent, text="Résultats", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        # Zone de texte pour les résultats
        self.text_resultats = tk.Text(result_frame, height=15, width=60)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.text_resultats.yview)
        self.text_resultats.configure(yscrollcommand=scrollbar.set)

        self.text_resultats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def executer_calcul(self):
        """Exécute les calculs réseau"""
        ip = self.entry_ip.get()
        masque = self.entry_masque.get()
        mode_classless = self.mode_var.get()

        if not CalculReseau.valider_ip(ip):
            messagebox.showerror("Erreur", "Adresse IP invalide")
            return

        if not CalculReseau.valider_masque(masque):
            messagebox.showerror("Erreur", "Masque de sous-réseau invalide")
            return

        resultat = CalculReseau.calculer_infos_reseau(ip, masque, mode_classless)

        self.text_resultats.delete(1.0, tk.END)

        if resultat['success']:
            texte_resultat = f"""
=== INFORMATIONS RÉSEAU ===

Adresse IP: {ip}
Masque: {masque}
Mode: {'Classless' if mode_classless else 'Classful'}

--- RÉSULTATS ---
Adresse réseau: {resultat['adresse_reseau']}
Masque CIDR: {resultat['masque_cidr']}
Masque sous-réseau: {resultat['masque_sous_reseau']}
Adresse broadcast: {resultat['adresse_broadcast']}
Première IP utilisable: {resultat['premiere_ip']}
Dernière IP utilisable: {resultat['derniere_ip']}
Nombre d'IPs utilisables: {resultat['nombre_ips']}
Classe IP: {resultat['classe']}
"""
        else:
            texte_resultat = f"ERREUR: {resultat['error']}"

        self.text_resultats.insert(1.0, texte_resultat)