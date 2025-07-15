# app/scanner/forensic_orchestrator.py (Corrected and Smarter)
import garak.attempt
from garak.detectors import goodside, unsafe_content

_forensic_orchestrator_instance = None


class ForensicOrchestrator:
    """Initializes a powerful, model-based suite of Garak detectors."""

    def __init__(self):
        print("Pre-loading Forensic detectors...")
        self.detectors = {
            # The best-in-class open source toxicity and unsafe content classifier.
            "toxicity_and_hate": unsafe_content.ToxicCommentModel(),
            # A great rules-based check for harmfulness categories.
            "goodside_rules": goodside.Rules(),
        }
        print("✅ Forensic orchestrator ready.")

    def analyze(self, prompt: str, response: str) -> dict:
        risk_profile = {}
        attempt = garak.attempt.Attempt()
        attempt.prompt = prompt
        attempt.outputs = [response]
        for name, detector in self.detectors.items():
            try:
                results = detector.detect(attempt)
                risk_profile[name] = round(max(results), 4) if results else 0.0
            except Exception as e:
                print(
                    f"INFO: Forensic detector '{name}' skipped. Reason: {str(e)[:100]}..."
                )
                risk_profile[name] = -1.0
        return risk_profile


def get_forensic_orchestrator():
    """Singleton factory for the ForensicOrchestrator."""
    global _forensic_orchestrator_instance
    if _forensic_orchestrator_instance is None:
        _forensic_orchestrator_instance = ForensicOrchestrator()
    return _forensic_orchestrator_instance
