import os

# convertir une chaîne en booléen
def str2bool(v: str) -> bool:
    return str(v).lower() in {"1", "true", "yes", "on"}

# ignorer les erreurs d'importation de .env 
def load_env(env_path: str = ".env"):
    # charger les variables d'environnement depuis un fichier .env
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
