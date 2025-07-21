# app/scanner/triage_classifier.py
import re

# High-confidence patterns that warrant an immediate block
BLOCK_PATTERNS = {
    # SQL Injection
    "SQLI_DROP": re.compile(r"\b(DROP\s+TABLE|DROP\s+DATABASE)\b", re.IGNORECASE),
    "SQLI_UNION": re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    # Command Injection
    "CMD_INJECT": re.compile(
        r";\s*(ls|dir|cat|whoami|rm|powershell|bash)\b", re.IGNORECASE
    ),
    # Basic XSS
    "XSS_SCRIPT": re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
}

# Patterns that are suspicious and require a deeper look
DEEP_SCAN_PATTERNS = {
    # Role-playing, DAN, etc.
    "ROLEPLAY": re.compile(
        r"\b(act\s+as|you\s+are\s+now|ignore\s+previous|developer\s+mode)\b",
        re.IGNORECASE,
    ),
    # Requests for code generation
    "CODE_GEN": re.compile(
        r"\b(write\s+a\s+(script|function|program)|import\s+\w|def\s+\w+\(.*\):)\b",
        re.IGNORECASE,
    ),
    # Potentially sensitive topics
    "SENSITIVE_KEYWORDS": re.compile(
        r"(bomb|self-harm|illegal|hate speech|steal|theft|phishing|malware|hack)",
        re.IGNORECASE,
    ),
}


class TriageClassifier:
    """
    A fast, regex-based classifier to perform initial triage on a prompt.
    """

    @staticmethod
    def classify(prompt: str) -> (str, str):
        """
        Classifies the prompt into one of three categories.

        Returns:
            A tuple of (decision, reason_string)
            decision: "BLOCK", "ALLOW", or "DEEP_SCAN"
            reason: A string explaining why the decision was made.
        """
        # 1. Check for high-confidence BLOCK patterns first
        for reason, pattern in BLOCK_PATTERNS.items():
            if pattern.search(prompt):
                print(f"🚨 Triage: BLOCKING prompt due to pattern: {reason}")
                return "BLOCK", reason

        # 2. Check for patterns that require a DEEP_SCAN
        for reason, pattern in DEEP_SCAN_PATTERNS.items():
            if pattern.search(prompt):
                print(f"🔬 Triage: Flagging for DEEP_SCAN due to pattern: {reason}")
                return "DEEP_SCAN", reason

        # 3. If no patterns matched, default to ALLOW for simple queries
        #    but DEEP_SCAN for longer, more complex ones as a safety measure.
        if len(prompt) > 500:  # Heuristic for complexity
            print("🔬 Triage: Flagging for DEEP_SCAN due to prompt length.")
            return "DEEP_SCAN", "COMPLEX_PROMPT"

        print("✅ Triage: ALLOWING prompt.")
        return "ALLOW", "BENIGN"
