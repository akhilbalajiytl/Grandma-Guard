"""
GrandmaGuard Garak Detector Loader Module

This module implements singleton-pattern loading and management of Garak security
detectors for the GrandmaGuard scanning system. It provides thread-safe,
lazy-loading capabilities for multiple security detection models, ensuring
efficient resource utilization in production environments.

Core Functionality:
- Singleton pattern for shared detector instances across application threads
- Thread-safe model loading with locking mechanisms
- Gunicorn worker initialization hooks for eager model loading
- Comprehensive security detector registry management
- Graceful error handling and fallback mechanisms

Detector Categories:
- Refusal Bypass: Custom refusal detection (refusal_v2)
- Jailbreak Detection: DAN and prompt injection attempts
- Code Injection: XSS, SQL injection, malicious code generation
- Content Safety: Toxicity, slurs, and harmful content detection
- Data Leakage: PII extraction and information replay attacks
- Product Security: Windows product key generation detection

The loader ensures that expensive model initialization occurs only once per
worker process while providing robust access patterns for concurrent requests.

Functions:
    get_analyzer: Thread-safe getter for shared ForensicAnalyzer instance
    gunicorn_post_worker_init: Gunicorn worker initialization hook

Author: GrandmaGuard Security Team
License: MIT
"""

# app/scanner/garak_loader.py
import logging
import threading

# Garak and detector imports
from garak.detectors import dan, exploitation, leakreplay, malwaregen, productkey, promptinject, unsafe_content, xss
from .detectors import refusal_v2
from .forensic_analyzer import ForensicAnalyzer
#from .smart_classifier import SmartClassifier # Assuming you might want to preload this too

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
    Initialize and preload all Garak security detectors and analysis models.
    
    This internal function performs one-time initialization of all security
    detection models used by GrandmaGuard. It creates instances of various
    Garak detectors and initializes the shared ForensicAnalyzer instance
    that coordinates security scanning operations.
    
    The function implements lazy loading and is designed to be thread-safe
    and idempotent - it can be called multiple times without side effects
    if the models are already loaded.
    
    Initialized Detectors:
    - refusal_v2: Custom refusal bypass detection
    - dan_detection: DAN jailbreak attempt detection
    - xss_markdown_basic: Cross-site scripting payload detection
    - sqli_echo: SQL injection attempt detection
    - python_code_execution: Malicious Python code detection
    - any_code_generated: General malware/harmful code detection
    - toxicity_comment_model: Toxic content classification
    - slur_detection: Slur and hate speech detection
    - leak_replay_startswith: PII leakage pattern detection
    - prompt_injection_rogue_string: Prompt injection detection
    - win_prodkey_5x5: Windows product key generation detection
    
    Side Effects:
        Sets the global ANALYZER_INSTANCE variable with initialized ForensicAnalyzer.
        Logs progress information during the loading process.
    
    Note:
        This function modifies global state and should only be called through
        the thread-safe get_analyzer() function in production code.
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
    Get the shared ForensicAnalyzer instance with thread-safe initialization.
    
    This function provides thread-safe access to the singleton ForensicAnalyzer
    instance, ensuring that detector models are loaded exactly once per worker
    process. It implements lazy loading with proper locking to handle concurrent
    requests during application startup.
    
    The function uses a threading lock to prevent race conditions when multiple
    threads attempt to initialize the analyzer simultaneously. Once initialized,
    subsequent calls return the cached instance without locking overhead.
    
    Returns:
        ForensicAnalyzer: Fully initialized analyzer instance with all Garak
                         detectors loaded and ready for security scanning operations.
    
    Raises:
        RuntimeError: If the ForensicAnalyzer initialization fails critically.
                     This indicates a fundamental system problem that prevents
                     security scanning from functioning.
    
    Example:
        >>> analyzer = get_analyzer()
        >>> results = analyzer.analyze_output("suspicious text", {"category": "test"})
        >>> print(results["scores"])
        {'refusal_v2': 0.1, 'dan_detection': 0.05, ...}
    
    Thread Safety:
        This function is safe to call from multiple threads concurrently.
        The first thread will perform initialization while others wait,
        and all threads will receive the same analyzer instance.
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
    """
    Gunicorn worker initialization hook for eager model loading.
    
    This function is designed to be called by Gunicorn's post_worker_init hook
    to perform eager loading of security detection models when each worker
    process starts. This approach improves first-request latency by avoiding
    lazy loading delays during production traffic.
    
    The function triggers the complete detector initialization process and
    provides detailed logging to track the loading progress across worker
    processes. This is particularly important in multi-worker deployments
    where each process needs its own model instances.
    
    Args:
        worker: Gunicorn worker instance providing process information and
               logging capabilities. The worker object contains process ID
               and logging methods for tracking initialization progress.
    
    Example:
        In gunicorn.conf.py:
        ```python
        from app.scanner.garak_loader import gunicorn_post_worker_init
        post_worker_init = gunicorn_post_worker_init
        ```
    
    Note:
        This function is specifically designed for Gunicorn deployments.
        For other WSGI servers or development environments, use get_analyzer()
        directly for lazy loading behavior.
    """
    worker.log.info(f"Gunicorn worker (pid: {worker.pid}) is initializing models eagerly.")
    get_analyzer() # This will trigger the loading process safely.
    worker.log.info(f"✅ Models initialized for Gunicorn worker (pid: {worker.pid}).")