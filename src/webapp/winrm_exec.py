import os

# fonction pour executer une commande powershell via winrm
def run_ps(command: str):

    host = os.environ.get("WINRM_HOST")
    username = os.environ.get("WINRM_USERNAME")
    password = os.environ.get("WINRM_PASSWORD")

    # verifier si le serveur est disponible ou non
    if not host:
        return "", "WINRM_HOST missing in .env"

    try:
        import winrm  # lazy import so the app starts without pywinrm installed
        # Création de session WinRM vers le serveur Windows
        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(username, password)
        )
        # execution  commande PowerShell
        result = session.run_ps(command)

        # stocker et decodage des resultats
        stdout = result.std_out.decode(errors="ignore")
        stderr = result.std_err.decode(errors="ignore")

        return stdout, stderr

    except Exception as e:
        # Si un probleme apparait
        return "", str(e)
