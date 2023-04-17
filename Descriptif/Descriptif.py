import re
import hashlib

# Fonction pour vérifier si le mot de passe respecte les exigences de sécurité
def password_validation(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*]", password):
        return False
    return True

# Demander à l'utilisateur de choisir un mot de passe
password = input("Choisissez un mot de passe : ")

# Vérifier si le mot de passe respecte les exigences de sécurité
while not password_validation(password):
    print("Le mot de passe doit contenir au moins 8 caractères, une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial (!, @, #, $, %, ^, &, *)")
    password = input("Choisissez un nouveau mot de passe : ")

# Hasher le mot de passe en utilisant l'algorithme SHA-256
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# Afficher le mot de passe hashé
print("Le mot de passe hashé est :", hashed_password)