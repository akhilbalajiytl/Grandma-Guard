"""
Garak CLI Integration Module

This module provides integration with garak's command-line interface to run
comprehensive security probes against LLM targets. It supports running all
garak probes as a complete security assessment separate from or in addition
to the existing payload-based tests.
"""

import subprocess
import json
import os
import tempfile
import yaml
from typing import Dict, List, Optional, Tuple
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)
    
class GarakCLIRunner:
    def __init__(self):
        self.garak_executable = "garak"
        self.temp_dir = tempfile.mkdtemp(prefix="grandma_garak_")
    
    # --- NEW METHOD TO CREATE THE CONFIG FILE ---
    def _create_garak_config_yaml(self, api_config: Dict) -> str:
        """Dynamically creates a Garak YAML config for any OpenAI-compatible endpoint."""
        # This structure matches the one you provided
        config_data = {
            "plugins": {
                "generators": {
                    # We give our custom generator a unique name to avoid conflicts
                    "grandmaguard_custom_model": {
                        "uri": api_config["endpoint"],
                        "api_key": api_config["key"]
                        # We can add other parameters like context_len here if needed
                    }
                }
            }
        }
        
        config_path = os.path.join(self.temp_dir, "garak_custom_config.yaml")
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f)
        
        logger.info(f"Generated Garak config for endpoint: {api_config['endpoint']}")
        return config_path
       
    def check_garak_availability(self) -> bool:
        try:
            # Using --version is a standard way to check for executables
            result = subprocess.run([self.garak_executable, "--version"], capture_output=True, text=True, check=True)
            logger.info(f"Garak found: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("Garak executable not found or failed to run. Is it installed in the environment?")
            return False
    
    def get_available_probes(self) -> List[str]:
        """Get list of available garak probes."""
        try:
            result = subprocess.run(
                [self.garak_executable, "--list_probes"], 
                capture_output=True, 
                text=True, 
                timeout=45
            )
            if result.returncode == 0:
                # Parse the output to extract probe names
                probes = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    # Look for lines that start with "probes:" and contain a module.class format
                    if line.startswith('probes:') and '.' in line:
                        # Extract probe name: "probes: dan.Dan_11_0" -> "dan.Dan_11_0"
                        parts = line.split()
                        if len(parts) >= 2:
                            probe_name = parts[1]
                            # Skip if it contains symbols like 🌟 or 💤 or is just a category
                            if not any(symbol in probe_name for symbol in ['🌟', '💤']) and '.' in probe_name:
                                probes.append(probe_name)
                logger.info(f"Successfully found {len(probes)} probes dynamically")
                return probes
        except subprocess.TimeoutExpired:
            logger.warning("Timeout while listing garak probes")
        except Exception as e:
            logger.error(f"Error listing garak probes: {e}")
        
        # Return default probe list if command fails
        return [
            "dan.Dan_11_0",
            "encoding.InjectBase64", 
            "lmrc.Bullying",
            "malwaregen.TopLevel",
            "packagehallucination.Python",
            "promptinject.HijackKillHumans",
            "continuation.ContinueSlursReclaimedSlurs",
            "leakreplay.NYTCloze",
            "encoding.InjectHex",
            "snowball.GraphConnectivity"
        ]
        
    def run_garak_scan(self, api_config: Dict) -> List[Dict]:
        if not self.check_garak_availability():
            return []
        
        report_prefix = os.path.join(self.temp_dir, f"garak_report_{api_config['model_id']}")
        
        # --- FINAL, SIMPLIFIED COMMAND LOGIC ---
        is_openai_endpoint = "api.openai.com" in api_config.get("endpoint", "")

        if is_openai_endpoint:
            logger.info("OpenAI endpoint detected. Using the native 'openai' Garak generator.")
            cmd = [
                self.garak_executable,
                "--model_type", "openai",
                "--model_name", api_config["model_id"],
                "--report_prefix", report_prefix,
                "--generations", "5",
                "--parallel_attempts", "16"
            ]
            # The native 'openai' generator will automatically look for the OPENAI_API_KEY
            # environment variable from the container's own environment.
            env = os.environ.copy()
            env["OPENAI_API_KEY"] = api_config["key"]
        else:
            logger.info(f"Custom endpoint detected ({api_config['endpoint']}). Using the 'nim' Garak generator.")
            config_file_path = self._create_garak_nim_config_yaml(api_config)
            cmd = [
                self.garak_executable,
                "--model_type", "nim",
                "--model_name", api_config["model_id"],
                "--config", config_file_path,
                "--report_prefix", report_prefix,
                "--generations", "5",
                "--parallel_attempts", "4"
            ]
            env = os.environ.copy()
        
        # Using a single probe for fast testing
        cmd.extend(["--probes", "grandma"])
        # --- END OF COMMAND LOGIC ---

        try:
            logger.info(f"Executing Garak command: {' '.join(cmd)}")
            
            # Use subprocess.run for simplicity and better error capture
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=7200, 
                env=env
            )

            # --- ROBUST ERROR CHECKING ---
            logger.info(f"Garak process finished with return code: {result.returncode}")
            if result.stdout:
                logger.info(f"Garak STDOUT:\n{result.stdout}")
            if result.stderr:
                logger.error(f"Garak STDERR:\n{result.stderr}")

            jsonl_report_path = f"{report_prefix}.report.jsonl"

            # Check BOTH return code and file existence
            if result.returncode != 0 or not os.path.exists(jsonl_report_path):
                logger.error("Garak scan failed to produce a valid report file.")
                return []
            # --- END OF ROBUST CHECKING ---

            probe_summaries = self._aggregate_garak_results(jsonl_report_path)
            return probe_summaries

        except subprocess.TimeoutExpired:
            logger.error("Garak scan timed out after 2 hours.")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred during Garak scan: {e}")
            return []
        finally:
            self.cleanup()
        
    # --- THIS IS THE NEW AGGREGATION LOGIC ---
    def _aggregate_garak_results(self, report_path: str) -> List[Dict]:
        """
        Reads a Garak JSONL report and correctly aggregates results per probe
        based on the observed log file structure.
        """
        probe_results: Dict[str, Dict] = {}

        with open(report_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    
                    # A valid attempt entry from Garak will always have 'entry_type': 'attempt'.
                    # This is a more robust check than just checking for 'prompt'.
                    if data.get("entry_type") != "attempt":
                        continue

                    # --- THIS IS THE FINAL, EVIDENCE-BASED FIX ---
                    # The raw log confirms the key for the sub-probe is 'probe_classname'.
                    probe_name = data.get("probe_classname", "unknown.probe")
                    # --- END OF FIX ---
                    
                    if probe_name not in probe_results:
                        probe_results[probe_name] = {"passed": 0, "failed": 0, "total": 0, "prompts": []}
                    
                    # The 'status' key in attempt entries is an integer: 1 = PASS.
                    # This is based on the raw log: "status": 1
                    probe_results[probe_name]["total"] += 1
                    if data.get("status") == 1:
                        probe_results[probe_name]["passed"] += 1
                    else:
                        probe_results[probe_name]["failed"] += 1
                    
                    if len(probe_results[probe_name]["prompts"]) < 5:
                         probe_results[probe_name]["prompts"].append({
                             "prompt": data.get("prompt"),
                             "output": data.get("outputs", [""])[0],
                             # Convert the integer status to our string status
                             "status": "PASS" if data.get("status") == 1 else "FAIL"
                         })

                except json.JSONDecodeError:
                    continue

        summaries = []
        for probe_name, stats in probe_results.items():
            total_count = stats["total"]
            passed_count = stats["passed"]
            
            summaries.append({
                "probe_name": probe_name,
                "status": "FAIL" if stats["failed"] > 0 else "PASS",
                "passed_count": passed_count,
                "failed_count": stats["failed"],
                "total_count": total_count,
                "pass_rate": (passed_count / total_count) if total_count > 0 else 1.0,
                "sample_prompts": stats["prompts"]
            })
        
        logger.info(f"Successfully aggregated results into {len(summaries)} probe summaries.")
        return summaries

    # --- THIS METHOD IS NOW CORRECTLY STRUCTURED FOR NIM ---
    def _create_garak_nim_config_yaml(self, api_config: Dict) -> str:
        """Dynamically creates a Garak YAML config for the NIM generator."""
        # This structure matches the one you provided.
        # We define a generator named 'nim' under the 'generators' key.
        config_data = {
            "plugins": {
                "generators": {
                    "nim": { # This key MUST be 'nim'
                        "uri": api_config["endpoint"],
                        "api_key": api_config["key"]
                        # We could add context_len here if needed
                    }
                }
            }
        }
        
        config_path = os.path.join(self.temp_dir, "garak_nim_config.yaml")
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f)
        
        logger.info(f"Generated Garak NIM config for endpoint: {api_config['endpoint']}")
        return config_path
    

    
    def _parse_garak_results(self, report_path: str) -> List[Dict]:
        """
        Parses the JSONL report from Garak into a structured format.
        NEW: Verdict is strictly PASS or FAIL. Defaults to FAIL for safety.
        """
        parsed = []
        with open(report_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    
                    # If the 'passed' key is explicitly True, it's a PASS.
                    # Any other case (False, missing, null) is treated as a FAIL.
                    # This is a secure-by-default posture.
                    if data.get("passed") is True:
                        status = "PASS"
                    else:
                        status = "FAIL"
                    # --- END OF NEW LOGIC ---

                    parsed.append({
                        "probe": data.get("probe_class", "unknown.probe"),
                        "prompt": data.get("prompt", "No prompt logged"),
                        "response": data.get("outputs", [""])[0],
                        "status": status, # Use the decisive PASS/FAIL status
                        "detector": data.get("detector_class", "unknown.detector"),
                        "raw_result": data
                    })
                except json.JSONDecodeError:
                    logger.warning(f"Skipping malformed line in Garak report: {line.strip()}")
        return parsed

    def cleanup(self):
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
            logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except OSError as e:
            logger.warning(f"Could not remove temp directory {self.temp_dir}: {e}")

# --- This function is now much simpler ---
def convert_garak_results_to_test_results(probe_summaries: List[Dict], run_id: int) -> List:
    """Converts a list of Garak probe summaries into TestResult DB objects."""
    from ..models import TestResult
    db_results = []
    for summary in probe_summaries:
        # The main payload/response will be a summary
        payload_summary = f"{summary['total_count']} prompts were tested for this probe."
        response_summary = f"Passed: {summary['passed_count']}, Failed: {summary['failed_count']}.\n"
        response_summary += "Sample prompts and responses are stored in the assessment details."

        db_results.append(TestResult(
            run_id=run_id,
            owasp_category=f"GARAK_{summary['probe_name'].replace('.', '_')}",
            payload=payload_summary,
            response=response_summary,
            status=summary["status"],
            garak_status=f"{summary['failed_count']} FAILED ({summary['pass_rate']:.1%})",
            llama_guard_status={"status": "NOT_RUN"},
            # Store the full summary, including sample prompts, in the details
            assessment_details=[summary] 
        ))
    return db_results
