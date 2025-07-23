# app/scanner/garak_loader.py
import logging

# --- Corrected, explicit imports ---
from garak.detectors.dan import DAN, DevMode
from garak.detectors.xss import MarkdownExfilBasic
from garak.detectors.exploitation import SQLiEcho, PythonCodeExecution
from garak.detectors.malwaregen import AnyCode
from garak.detectors.unsafe_content import ToxicCommentModel, SlursReclaimedSlurs
from garak.detectors.leakreplay import StartsWith
from garak.detectors.promptinject import AttackRogueString
from garak.detectors.productkey import Win5x5

# Your custom detector
from .detectors import refusal_v2

# Your other app components
from .smart_classifier import SmartClassifier
from .forensic_analyzer import ForensicAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# This will be our single, shared, pre-loaded instance.
ANALYZER_INSTANCE = None
CLASSIFIER_INSTANCE = None


def _load_dependencies():
    global ANALYZER_INSTANCE, CLASSIFIER_INSTANCE
    if ANALYZER_INSTANCE: return

    logger.info("Pre-loading Garak detectors...")
    garak_detectors = {
        # We now instantiate using the directly imported classes
        "refusal_v2": refusal_v2.RefusalDetectorV2(),
        "dan_detection": DAN(),
        "dev_mode_detection": DevMode(),
        "xss_markdown_basic": MarkdownExfilBasic(),
        "sqli_echo": SQLiEcho(),
        "python_code_execution": PythonCodeExecution(),
        "any_code_generated": AnyCode(),
        "toxicity_comment_model": ToxicCommentModel(),
        "slur_detection": SlursReclaimedSlurs(),
        "leak_replay_startswith": StartsWith(),
        "prompt_injection_rogue_string": AttackRogueString(),
        "win_prodkey_5x5": Win5x5(),
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