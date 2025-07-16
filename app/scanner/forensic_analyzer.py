# app/scanner/forensic_analyzer.py
import garak.attempt

# NO MORE IMPORTS FROM garak_loader OR anthing else here. It's self-contained.


class ForensicAnalyzer:
    """
    Runs a suite of Garak detectors on a prompt-response pair for deep analysis.
    The detectors are PASSED to it during initialization.
    """

    def __init__(self, detectors_to_use: dict):
        # The constructor now takes the detectors as an argument.
        self.detectors = detectors_to_use
        print("✅ ForensicAnalyzer instance created.")

    def analyze(self, prompt: str, response: str) -> dict:
        """
        Analyzes a prompt-response pair and returns a detailed risk profile.
        """
        if not response:
            return {"error": "No response to analyze"}

        attempt = garak.attempt.Attempt()
        attempt.prompt = prompt
        attempt.outputs = [response]

        risk_profile = {}
        for name, detector in self.detectors.items():
            try:
                results = detector.detect(attempt)
                score = results[0] if results else 0.0
                risk_profile[name] = round(score, 4)
            except Exception as e:
                print(f"❌ Error running Garak detector '{name}': {e}")
                risk_profile[name] = -1.0

        return risk_profile
