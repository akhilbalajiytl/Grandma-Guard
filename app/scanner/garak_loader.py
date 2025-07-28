# app/scanner/garak_loader.py
import logging
import threading

# Garak and detector imports
from garak.detectors import dan, exploitation, leakreplay, malwaregen, productkey, promptinject, unsafe_content, xss
from .detectors import refusal_v2
from .forensic_analyzer import ForensicAnalyzer
from .smart_classifier import SmartClassifier # Assuming you might want to preload this too

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Singleton Pattern Implementation ---
# This will hold our single, shared, pre-loaded instance.
ANALYZER_INSTANCE = None
# A lock to prevent two threads from trying to load the models at the same time
MODEL_LOCK = threading.Lock()
# ------------------------------------

def _load_dependencies():
    """
    Instantiates all detectors and creates the single ForensicAnalyzer instance.
    This function is now designed to be safe to call multiple times.
    """
    global ANALYZER_INSTANCE
    # If the instance already exists, do nothing.
    if ANALYZER_INSTANCE:
        return

    logger.info("Pre-loading Garak detectors and other models...")
    # NOTE: In a multi-worker setup, this will print for each worker process.
    garak_detectors = {
        "refusal_v2": refusal_v2.RefusalDetectorV2(),
        "dan_detection": dan.DAN(),
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

    # You could also preload your SmartClassifier here if using the local version
    # smart_classifier = SmartClassifier()
    # logger.info("✅ SmartClassifier pre-loaded.")

    logger.info("Creating shared ForensicAnalyzer instance...")
    ANALYZER_INSTANCE = ForensicAnalyzer(detectors_to_use=garak_detectors)
    logger.info("✅ Shared ForensicAnalyzer instance created and ready.")


def get_analyzer():
    """
    A getter function that ensures the models are loaded before returning the instance.
    This is now thread-safe and robust.
    """
    # Use a lock to ensure that even if multiple threads call this at the same
    # time, the loading process only happens once.
    with MODEL_LOCK:
        if ANALYZER_INSTANCE is None:
            # If the models haven't been loaded yet in this process, load them.
            _load_dependencies()
    
    # The original check is still a good safeguard.
    if ANALYZER_INSTANCE is None:
        raise RuntimeError("ForensicAnalyzer initialization failed critically.")
        
    return ANALYZER_INSTANCE

# --- Optional: Keep the Gunicorn hook for eager loading ---
# It's still a good idea to load the models when the worker starts, rather
# than waiting for the first request. The get_analyzer() is now just a robust fallback.
def gunicorn_post_worker_init(worker):
    """A wrapper function to be called by gunicorn.conf.py"""
    worker.log.info(f"Gunicorn worker (pid: {worker.pid}) is initializing models eagerly.")
    get_analyzer() # This will trigger the loading process safely.
    worker.log.info(f"✅ Models initialized for Gunicorn worker (pid: {worker.pid}).")