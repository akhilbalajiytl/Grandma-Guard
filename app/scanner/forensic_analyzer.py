"""
GrandmaGuard Forensic Analysis Module

This module implements deep forensic analysis capabilities for AI-generated
content using a comprehensive suite of Garak security detectors. The forensic
analyzer provides detailed risk profiling of prompt-response pairs to identify
potential security violations and harmful content generation.

Core Functionality:
- Multi-detector security analysis of AI interactions
- Comprehensive risk scoring across multiple threat categories
- Garak framework integration for production-grade threat detection
- Detailed error handling and graceful degradation
- Structured risk profiling for downstream policy decisions

The forensic analyzer serves as the comprehensive analysis engine in
GrandmaGuard's security pipeline, providing detailed threat assessment
for security incident investigation and policy enforcement.

Classes:
    ForensicAnalyzer: Main forensic analysis engine with Garak detector suite

Security Analysis Coverage:
- Content Safety: Toxicity, hate speech, and harmful content detection
- Injection Attacks: Prompt injection and jailbreak attempt identification
- Code Security: Malicious code generation and exploitation attempts
- Data Protection: PII leakage and information disclosure detection
- Web Security: XSS, injection, and web-based attack vectors

Author: GrandmaGuard Security Team
License: MIT
"""

# app/scanner/forensic_analyzer.py
import garak.attempt


class ForensicAnalyzer:
    """
    Deep forensic analysis engine using comprehensive Garak detector suite.
    
    This class coordinates multiple security detectors to perform comprehensive
    forensic analysis of AI prompt-response pairs. It provides detailed risk
    profiling across multiple security dimensions, enabling thorough post-
    generation security assessment and incident investigation.
    
    The analyzer accepts a configurable set of Garak detectors during
    initialization, allowing flexible security coverage based on deployment
    requirements and performance constraints. Each detector contributes
    specialized threat detection capabilities to the overall analysis.
    
    Key Features:
    - Configurable detector suite for flexible security coverage
    - Normalized risk scoring (0.0-1.0) across all detectors
    - Comprehensive error handling with graceful degradation
    - Detailed risk profiling for security decision support
    - Production-optimized for real-time forensic analysis
    
    Attributes:
        detectors (dict): Dictionary mapping detector names to detector instances.
                         Each detector implements the Garak detection interface.
    
    Example:
        >>> detectors = {
        ...     "toxicity": ToxicityDetector(),
        ...     "jailbreak": JailbreakDetector()
        ... }
        >>> analyzer = ForensicAnalyzer(detectors)
        >>> risk_profile = analyzer.analyze("Hello", "Harmful response")
        >>> print(risk_profile)
        {'toxicity': 0.8, 'jailbreak': 0.1}
    """
    
    def __init__(self, detectors_to_use: dict):
        """
        Initialize forensic analyzer with specified detector suite.
        
        Args:
            detectors_to_use (dict): Dictionary mapping detector names (str) to
                                   detector instances. Each detector must implement
                                   the Garak detection interface with detect() method.
        """
        # The constructor now takes the detectors as an argument.
        self.detectors = detectors_to_use
        print("✅ ForensicAnalyzer instance created.")

    def analyze(self, prompt: str, response: str) -> dict:
        """
        Perform comprehensive forensic analysis of prompt-response interaction.
        
        This method conducts deep security analysis using the full suite of
        configured Garak detectors. Each detector evaluates the interaction
        from its specialized perspective, contributing to a comprehensive
        risk profile that covers multiple security dimensions.
        
        The analysis uses Garak's Attempt structure to standardize the
        interaction format across all detectors, ensuring consistent
        evaluation and reliable risk scoring.
        
        Args:
            prompt (str): The user prompt or input that generated the response.
                         Used for context-aware analysis and injection detection.
            response (str): The AI-generated response to analyze for security
                           violations, harmful content, or policy breaches.
        
        Returns:
            dict: Comprehensive risk profile mapping detector names to risk scores.
                 Risk scores are normalized between 0.0 (safe) and 1.0 (high risk).
                 Returns {"error": "message"} if response is empty or invalid.
                 Failed detectors are marked with score -1.0 for identification.
        
        Example:
            >>> analyzer = ForensicAnalyzer(detector_suite)
            >>> profile = analyzer.analyze(
            ...     "How to hack?",
            ...     "Here's how to perform SQL injection..."
            ... )
            >>> print(profile)
            {
                'sqli_detection': 0.95,
                'code_injection': 0.88,
                'toxicity': 0.2,
                'refusal_bypass': 0.7
            }
        
        Note:
            Empty responses return an error dict. Detector failures are logged
            and marked with -1.0 scores to distinguish from legitimate low-risk
            scores (0.0). This enables proper error handling in downstream
            policy enforcement systems.
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