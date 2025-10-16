# main.py - commun
import tkinter as tk
from tkinter import ttk, messagebox
import database
from point1 import InterfaceCalculReseau
from point2 import InterfaceVerificationIP
from point4 import InterfaceDecoupeSR  # ton point4 intégré

class GestionnairePrincipal:
    def __init__(self):
        self.root = None
        self.db = database.DatabaseManager()

    def demarrer(self):
        """Démarre l'application avec l'interface de login"""
        self.root = tk.Tk()
        self.root.title("Gestionnaire Réseau - Connexion")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        self.creer_interface_login()
        self.root.mainloop()

    def creer_interface_login(self):
        """Crée l'interface de connexion"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        titre = ttk.Label(main_frame, text="Gestionnaire Réseau", font=("Arial", 16, "bold"))
        titre.pack(pady=(0, 20))

        champ_frame = ttk.Frame(main_frame)
        champ_frame.pack(pady=10)

        ttk.Label(champ_frame, text="Nom d'utilisateur:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_username = ttk.Entry(champ_frame, width=20)
        self.entry_username.grid(row=0, column=1, pady=5, padx=(10, 0))

        ttk.Label(champ_frame, text="Mot de passe:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_password = ttk.Entry(champ_frame, show="*", width=20)
        self.entry_password.grid(row=1, column=1, pady=5, padx=(10, 0))

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Se connecter", command=self.connexion).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="S'inscrire", command=self.inscription).pack(side=tk.LEFT, padx=5)

        self.entry_username.focus()
        self.entry_password.bind('<Return>', lambda event: self.connexion())

    def connexion(self):
        """Gère la connexion"""
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return

        if self.db.verify_user(username, password):
            messagebox.showinfo("Succès", "Connexion réussie!")
            self.current_user = username  # <-- on stocke l'utilisateur connecté
            self.root.destroy()
            self.creer_interface_principale()
        else:
            messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect")

    def inscription(self):
        """Gère l'inscription"""
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return

        if len(password) < 4:
            messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 4 caractères")
            return

        if self.db.add_user(username, password):
            messagebox.showinfo("Succès", "Inscription réussie! Vous pouvez maintenant vous connecter.")
        else:
            messagebox.showerror("Erreur", "Ce nom d'utilisateur existe déjà")

    def creer_interface_principale(self):
        """Crée l'interface principale après connexion"""
        main_window = tk.Tk()
        main_window.title("Gestionnaire Réseau - Outils")
        main_window.geometry("700x600")

        notebook = ttk.Notebook(main_window)

        # Onglet Découpe Sous-Réseaux (ton point4)
        frame_decoupe = ttk.Frame(notebook, padding="10")
        InterfaceDecoupeSR(frame_decoupe, self.current_user)  # <-- on utilise self.current_user
        notebook.add(frame_decoupe, text="Découpe Sous-Réseaux")

        # Onglet Vérification IP
        frame_verification = ttk.Frame(notebook, padding="10")
        InterfaceVerificationIP(frame_verification)
        notebook.add(frame_verification, text="Vérification IP")

        # Onglet Découpe Sous-Réseaux (ton point4)
        frame_decoupe = ttk.Frame(notebook, padding="10")
        InterfaceDecoupeSR(frame_decoupe, username)
        notebook.add(frame_decoupe, text="Découpe Sous-Réseaux")

        notebook.pack(expand=True, fill='both')
        main_window.mainloop()


if __name__ == "__main__":
    app = GestionnairePrincipal()
    app.demarrer()
