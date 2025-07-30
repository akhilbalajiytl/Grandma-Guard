"""
GrandmaGuard Garak Detector Registry Module

This module implements a comprehensive registry system for managing Garak
security detectors and probes within the GrandmaGuard scanning framework.
The registry provides dynamic discovery, capability mapping, and intelligent
selection of appropriate security detectors based on threat categories.

Core Functionality:
- Dynamic detector/probe discovery and instantiation
- Capability-based detector selection for specific threat types
- Comprehensive mapping of detector categories to security domains
- Performance optimization through detector caching
- Flexible configuration for custom detector integration

Security Coverage Areas:
- Toxicity & Hate Speech: Content safety and harmful language detection
- Prompt Injection & Jailbreaking: Safety mechanism bypass attempts
- Code & Exploitation: Malicious code generation and injection attacks
- Data Leakage & Privacy: PII extraction and information disclosure
- Misinformation & Misleading: False information and contradiction detection
- XSS & Web Security: Cross-site scripting and web-based attacks
- Encoding & Obfuscation: Evasion techniques and encoded payloads

The registry enables intelligent threat detection by automatically selecting
the most appropriate detectors for specific security assessment scenarios,
optimizing both coverage and performance in production environments.

Classes:
    GarakDetectorRegistry: Main registry for detector management and selection

Author: GrandmaGuard Security Team
License: MIT
"""

# app/scanner/garak_registry.py
import importlib
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class GarakDetectorRegistry:
    """
    Registry for managing Garak security detectors and their capabilities.
    
    This class provides a centralized registry for discovering, instantiating,
    and managing Garak security detectors and probes. It maintains comprehensive
    mappings between detector names and their security capabilities, enabling
    intelligent selection of appropriate detectors for specific threat scenarios.
    
    The registry implements caching to avoid repeated instantiation of expensive
    detector models and provides flexible querying capabilities for both exact
    detector names and capability-based selection.
    
    Key Features:
    - Dynamic detector discovery and instantiation from module paths
    - Capability-based detector selection for threat-specific scanning
    - Performance optimization through intelligent caching
    - Comprehensive security domain coverage mapping
    - Support for both built-in and custom detector integration
    
    Attributes:
        detector_cache (dict): Cache of instantiated detector objects
        detector_capabilities (dict): Mapping of detector names to capability tags
        probe_capabilities (dict): Mapping of probe names to capability tags
    
    Example:
        >>> registry = GarakDetectorRegistry()
        >>> toxicity_detectors = registry.get_detectors_by_capability(['toxicity'])
        >>> jailbreak_detectors = registry.get_detectors_by_capability(['jailbreak'])
        >>> detector = registry.get_detector('dan.DAN')
    """

    def __init__(self):
        self.detector_cache = {}

        # CORRECTED detector capabilities using actual Garak detectors
        self.detector_capabilities = {
            # Toxicity & Hate Speech
            "perspective.Toxicity": ["toxicity", "hate_speech", "offensive"],
            "perspective.Severe_Toxicity": ["severe_toxicity", "hate_speech"],
            "perspective.Identity_Attack": ["identity_attack", "discrimination"],
            "perspective.Insult": ["insult", "offensive"],
            "perspective.Profanity": ["profanity", "offensive"],
            "perspective.Threat": ["threat", "violence"],
            "lmrc.Anthro": ["toxicity", "anthropic_style"],
            # Unsafe Content
            "unsafe_content.ToxicCommentModel": ["toxicity", "harmful_content"],
            "unsafe_content.LDNOOBW": ["profanity", "offensive"],
            "unsafe_content.SlursReclaimedSlurs": ["slurs", "hate_speech"],
            # Prompt Injection & Jailbreaking
            "promptinject.AttackRogueString": ["prompt_injection", "system_prompt"],
            "dan.DAN": ["jailbreak", "roleplay_attack"],
            "dan.AntiDAN": ["jailbreak", "dan_detection"],
            "dan.DANJailbreak": ["jailbreak", "dan_style"],
            "dan.DUDE": ["jailbreak", "roleplay"],
            "dan.DevMode": ["jailbreak", "developer_mode"],
            "dan.STAN": ["jailbreak", "roleplay"],
            # Code & Exploitation
            "exploitation.PythonCodeExecution": ["code_execution", "security"],
            "exploitation.SQLiEcho": ["sql_injection", "database"],
            "exploitation.SQLiSuccess": ["sql_injection", "database"],
            "malwaregen.AnyCode": ["malware", "code_generation"],
            # Encoding & Obfuscation
            "encoding.DecodeApprox": ["encoding_attack", "obfuscation"],
            "encoding.DecodeMatch": ["encoding_attack", "obfuscation"],
            "ansiescape.Escaped": ["ansi_escape", "terminal_injection"],
            # Misinformation & Misleading
            "misleading.MustContradictNLI": ["misinformation", "contradiction"],
            "misleading.MustRefuteClaimKW": ["misinformation", "false_claims"],
            "misleading.MustRefuteClaimModel": ["misinformation", "false_claims"],
            # Data Leakage & Privacy
            "leakreplay.StartsWith": ["data_leakage", "privacy"],
            "packagehallucination.PythonPypi": ["hallucination", "package_names"],
            "packagehallucination.JavaScriptNpm": ["hallucination", "package_names"],
            # XSS & Web Security
            "xss.MarkdownExfilBasic": ["xss", "markdown_injection"],
            "xss.MarkdownExfilContent": ["xss", "content_injection"],
            # General Safety & Refusal
            "judge.Refusal": ["refusal", "safety", "general"],
            "judge.ModelAsJudge": ["general_safety", "llm_judge"],
            "mitigation.MitigationBypass": ["safety_bypass", "mitigation"],
            # Always include our custom detector
            "refusal_v2.RefusalDetectorV2": ["refusal", "safety", "general"],
        }

        # CORRECTED probe capabilities using actual Garak probes
        self.probe_capabilities = {
            # Toxicity & Hate Speech
            "lmrc.Profanity": ["profanity", "toxicity"],
            "lmrc.Anthro": ["toxicity", "anthropic_style"],
            # Jailbreaking & DAN
            "dan.DAN_11_0": ["jailbreak", "dan_attack"],
            "dan.DAN_Jailbreak": ["jailbreak", "dan_style"],
            "dan.DUDE_Jailbreak": ["jailbreak", "dude_style"],
            "dan.ChatGPT_Developer_Mode_RANTI": ["jailbreak", "developer_mode"],
            # Prompt Injection
            "promptinject.AttackRogueString": ["prompt_injection", "system_prompt"],
            # Encoding Attacks
            "encoding.InjectBase64": ["encoding_attack", "base64"],
            "encoding.InjectHex": ["encoding_attack", "hex"],
            "encoding.InjectROT13": ["encoding_attack", "rot13"],
            "encoding.InjectUnicode": ["encoding_attack", "unicode"],
            # Continuation & Divergence
            "continuation.ContinueSlurs": ["continuation", "slurs"],
            "continuation.ContinueToxic": ["continuation", "toxicity"],
            # Malware Generation
            "malwaregen.Malware": ["malware", "code_generation"],
            # Package Hallucination
            "packagehallucination.PythonPypi": ["hallucination", "python_packages"],
            "packagehallucination.JavaScriptNpm": ["hallucination", "npm_packages"],
            # Misleading Information
            "misleading.FalseAssertion": ["misinformation", "false_claims"],
            # Visual Jailbreak (if available)
            "visual_jailbreak.FigStep": ["visual_jailbreak", "image_attack"],
        }

    def get_detector(self, detector_name: str):
        """Get or create a detector instance"""
        if detector_name not in self.detector_cache:
            try:
                module_path, class_name = detector_name.rsplit(".", 1)
                module = importlib.import_module(f"garak.detectors.{module_path}")
                detector_class = getattr(module, class_name)
                self.detector_cache[detector_name] = detector_class()
                logger.info(f"✅ Loaded detector: {detector_name}")
            except Exception as e:
                logger.error(f"❌ Failed to load detector {detector_name}: {e}")
                return None

        return self.detector_cache[detector_name]

    def get_probe_detector_pairs(self, category: str) -> List[Dict[str, str]]:
        """Get recommended probe-detector pairs for a payload category"""
        category_lower = category.lower()
        pairs = []

        # Find matching probes and detectors
        matching_probes = []
        matching_detectors = []

        for probe, capabilities in self.probe_capabilities.items():
            if any(cap in category_lower for cap in capabilities):
                matching_probes.append(probe)

        for detector, capabilities in self.detector_capabilities.items():
            if any(cap in category_lower for cap in capabilities):
                matching_detectors.append(detector)

        # Create logical pairs
        if "toxicity" in category_lower:
            pairs.extend(
                [
                    {"probe": "lmrc.Profanity", "detector": "perspective.Toxicity"},
                    {"probe": "lmrc.Profanity", "detector": "perspective.Profanity"},
                    {
                        "probe": "continuation.ContinueToxic",
                        "detector": "perspective.Severe_Toxicity",
                    },
                ]
            )

        elif "jailbreak" in category_lower:
            pairs.extend(
                [
                    {"probe": "dan.DAN_11_0", "detector": "dan.DAN"},
                    {"probe": "dan.DAN_11_0", "detector": "judge.Refusal"},
                    {"probe": "dan.DUDE_Jailbreak", "detector": "dan.AntiDAN"},
                ]
            )

        elif "prompt_injection" in category_lower:
            pairs.extend(
                [
                    {
                        "probe": "promptinject.AttackRogueString",
                        "detector": "promptinject.AttackRogueString",
                    },
                    {
                        "probe": "promptinject.AttackRogueString",
                        "detector": "judge.Refusal",
                    },
                ]
            )

        elif "encoding" in category_lower or "adversarial" in category_lower:
            pairs.extend(
                [
                    {
                        "probe": "encoding.InjectBase64",
                        "detector": "encoding.DecodeMatch",
                    },
                    {
                        "probe": "encoding.InjectHex",
                        "detector": "encoding.DecodeApprox",
                    },
                    {"probe": "encoding.InjectUnicode", "detector": "judge.Refusal"},
                ]
            )

        elif "malware" in category_lower:
            pairs.extend(
                [
                    {"probe": "malwaregen.Malware", "detector": "malwaregen.AnyCode"},
                    {"probe": "malwaregen.Malware", "detector": "judge.Refusal"},
                ]
            )

        # Always add general safety pair as fallback
        pairs.append({"probe": None, "detector": "judge.Refusal"})
        pairs.append({"probe": None, "detector": "refusal_v2.RefusalDetectorV2"})

        return pairs
