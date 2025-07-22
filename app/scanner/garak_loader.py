# app/scanner/garak_loader.py
import logging

from garak.detectors import (
    dan,
    exploitation,
    leakreplay,
    malwaregen,
    productkey,
    promptinject,
    unsafe_content,
    xss,
)

from .detectors import refusal_v2

# IMPORTANT: Import ForensicAnalyzer here. This is now a one-way dependency.
from .forensic_analyzer import ForensicAnalyzer
from .smart_classifier import SmartClassifier


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# This will be our single, shared, pre-loaded instance.
ANALYZER_INSTANCE = None
CLASSIFIER_INSTANCE = None


def _load_dependencies():
    """
    Instantiates all detectors and creates the single ForensicAnalyzer instance.
    This function is called once per worker.
    """
    global ANALYZER_INSTANCE, CLASSIFIER_INSTANCE

    if ANALYZER_INSTANCE:  # Prevent re-loading
        return

    logger.info("Pre-loading Garak detectors...")
    garak_detectors = {
        "refusal_v2": refusal_v2.RefusalDetectorV2(),
        "dan_detection": dan.DAN(),
        "dev_mode_detection": dan.DevMode(),
        "xss_markdown_basic": xss.MarkdownExfilBasic(),
        "sqli_echo": exploitation.SQLiEcho(),
        "python_code_execution": exploitation.PythonCodeExecution(),
        "any_code_generated": malwaregen.AnyCode(),
        "toxicity_comment_model": unsafe_content.ToxicCommentModel(),
        "slur_detection": unsafe_content.SlursReclaimedSlurs(),
        "leak_replay_startswith": leakreplay.StartsWith(),
        "prompt_injection_rogue_string": promptinject.AttackRogueString(),
        "win_prodkey_5x5": productkey.Win5x5(),
    }
    logger.info("✅ All Garak detectors pre-loaded.")

    logger.info("Creating shared ForensicAnalyzer instance...")
    # Create the analyzer and PASS the detectors to it.
    ANALYZER_INSTANCE = ForensicAnalyzer(detectors_to_use=garak_detectors)
    logger.info("✅ Shared ForensicAnalyzer instance created and ready.")

    # --- Load the SmartClassifier ---
    logger.info("Loading Smart Triage Classifier model...")
    CLASSIFIER_INSTANCE = SmartClassifier()
    logger.info("✅ Smart Triage Classifier loaded and ready.")

def get_analyzer():
    """
    A getter function to safely access the shared analyzer instance.
    """
    if ANALYZER_INSTANCE is None:
        raise RuntimeError(
            "ForensicAnalyzer has not been initialized. Models are not loaded."
        )
    return ANALYZER_INSTANCE

# --- Getter function for the classifier ---
def get_classifier():
    """
    A getter function to safely access the shared smart classifier instance.
    """
    if CLASSIFIER_INSTANCE is None:
        raise RuntimeError("SmartClassifier has not been initialized.")
    return CLASSIFIER_INSTANCE