# app/scanner/triage_orchestrator.py
import garak.attempt
from garak.detectors import dan, knownbadsignatures, promptinject, xss
from garak.detectors.mitigation import MitigationBypass

_triage_orchestrator_instance = None


class TriageOrchestrator:
    def __init__(self):
        print("Pre-loading Triage detectors...")
        self.detectors = {
            "dan_jailbreak": dan.DANJailbreak(),
            "known_bad_signature": knownbadsignatures.EICAR(),
            "xss_vuln": xss.MarkdownExfilBasic(),
            "prompt_injection": promptinject.AttackRogueString(),
        }
        self.mitigation_detector = MitigationBypass()
        print("✅ Triage orchestrator ready.")

    def analyze(self, prompt: str, response: str) -> dict:
        risk_profile = {}
        attempt = garak.attempt.Attempt()
        attempt.prompt = prompt
        attempt.outputs = [response]

        # Run standard detectors where a high score means high risk
        for name, detector in self.detectors.items():
            try:
                results = detector.detect(attempt)
                risk_profile[name] = round(max(results), 4) if results else 0.0
            except Exception:
                risk_profile[name] = -1.0

        # Run the special MitigationBypass detector
        # It returns 1.0 if there is NO mitigation/refusal.
        try:
            mitigation_results = self.mitigation_detector.detect(attempt)
            # A score of 1.0 means "no refusal found". This is only a risk if
            # the prompt was actually harmful. We log it for the policy engine.
            risk_profile["no_refusal"] = (
                round(max(mitigation_results), 4) if mitigation_results else 0.0
            )
        except Exception:
            risk_profile["no_refusal"] = -1.0

        return risk_profile


def get_triage_orchestrator():
    """
    Singleton factory for the TriageOrchestrator.
    Creates the instance on the first call and returns the existing instance on subsequent calls.
    """
    global _triage_orchestrator_instance
    if _triage_orchestrator_instance is None:
        _triage_orchestrator_instance = TriageOrchestrator()
    return _triage_orchestrator_instance
