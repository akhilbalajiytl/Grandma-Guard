# app/scanner/garak_registry.py
import importlib
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class GarakDetectorRegistry:
    """Registry for managing Garak detectors and their capabilities"""

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
