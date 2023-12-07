import hashlib
import json

def verifier(mot_de_passe):
    majuscule_presente = any(c.isupper() for c in mot_de_passe)
    minuscule_presente = any(c.islower() for c in mot_de_passe)
    chiffre_present = any(c.isdigit() for c in mot_de_passe)
    special_present = any(c in "!@#$%^&*" for c in mot_de_passe)

    return majuscule_presente and minuscule_presente and chiffre_present and special_present

def hasher_mot_de_passe(mot_de_passe):
    sha256 = hashlib.sha256()
    sha256.update(mot_de_passe.encode('utf-8'))
    mot_de_passe_hash = sha256.hexdigest()
    return mot_de_passe_hash

mot_de_passe_valide = False

while not mot_de_passe_valide:
    mot_de_passe_utilisateur = input("Choisissez un mot de passe : ")

    if len(mot_de_passe_utilisateur) < 8:
        print("Erreur : Le mot de passe doit contenir au moins 8 caractères.")
    elif not any(c.isdigit() for c in mot_de_passe_utilisateur):
        print("Erreur : Le mot de passe doit contenir au moins un chiffre.")
    elif not any(c.isupper() for c in mot_de_passe_utilisateur):
        print("Erreur : Le mot de passe doit contenir au moins une lettre majuscule.")
    elif not any(c.islower() for c in mot_de_passe_utilisateur):
        print("Erreur : Le mot de passe doit contenir au moins une lettre minuscule.")
    elif not any(c in "!@#$%^&*" for c in mot_de_passe_utilisateur):
        print("Erreur : Le mot de passe doit contenir au moins un caractère spécial.")
    else:
        mot_de_passe_valide = True
        print("Mot de passe valide !")
        break

mot_de_passe_hash = hasher_mot_de_passe(mot_de_passe_utilisateur)



with open("mots_de_passe.json", "w") as fichier_json:
    json.dump(mot_de_passe_hash, fichier_json)


with open("mots_de_passe.json", "r") as fichier_json:
    json.load(fichier_json)

