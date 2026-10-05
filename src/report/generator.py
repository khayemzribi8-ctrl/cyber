# src/report/generator.py
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from pathlib import Path
import pandas as pd
import logging

# Configurer un logger simple pour debug
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def render_html(sections, out_path: str, templates_dir: str = None):
    """
    Génère le rapport HTML à partir du template Jinja2.

    Args:
        sections: Liste des sections à afficher dans le rapport
        out_path: Chemin complet du fichier HTML à générer
        templates_dir: Dossier contenant les templates (par défaut : dossier 'templates' à côté de ce fichier)
    """
    # Déterminer automatiquement le dossier templates (même si on lance depuis src/)
    if templates_dir is None:
        # Chemin absolu vers le dossier templates à la racine du projet
        templates_dir = Path(__file__).parent.parent.parent / "templates"

    templates_path = Path(templates_dir)

    if not templates_path.exists():
        raise FileNotFoundError(
            f"Dossier templates non trouvé : {templates_path.resolve()}")

    logger.info(
        f"Chargement des templates depuis : {templates_path.resolve()}")

    try:
        env = Environment(loader=FileSystemLoader(str(templates_path)))
        tpl = env.get_template("report.html.j2")
    except TemplateNotFound as e:
        raise TemplateNotFound(
            f"Template 'report.html.j2' non trouvé dans {templates_path}. Erreur : {e}")

    html_content = tpl.render(
    sections=sections,
    generated_at=datetime.utcnow().strftime("%d %B %Y à %H:%M") 
)
    
    # Créer le dossier de sortie si nécessaire
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Écrire le fichier
    Path(out_path).write_text(html_content, encoding="utf-8")
    logger.info(f"Rapport HTML généré : {out_path}")
    
    return out_path

def export_csv(df: pd.DataFrame, out_path: str):
    """
    Exporte un DataFrame en CSV.
    """
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False, encoding="utf-8")
    logger.info(f"Rapport CSV généré : {out_path}")
    return out_path