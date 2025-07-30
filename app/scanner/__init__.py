"""GrandmaGuard Scanner Module.

This package contains the core security scanning functionality for the GrandmaGuard
AI safety and security testing framework. It provides comprehensive tools for
detecting and preventing various forms of AI misuse and security threats.

Key Components:
    - engine: Main scanning orchestration and workflow management
    - runtime_scanner: Real-time security scanning for proxy operations
    - smart_classifier: AI-powered content classification and threat detection
    - garak_wrapper: Integration with Garak AI red-teaming framework
    - llama_guard: Meta's LlamaGuard safety classifier integration
    - forensic_analyzer: Deep security analysis and incident investigation
    - policy_engine: Configurable security policy enforcement
    - detectors/: Specialized threat detection modules
    - reporting/: Security assessment reporting and visualization

Security Capabilities:
    - Prompt injection detection and prevention
    - Jailbreak attempt identification
    - Content safety and appropriateness analysis
    - Multi-layered scanning with diverse AI safety tools
    - Real-time threat filtering for production environments
    - Comprehensive audit logging and forensic analysis

Architecture:
    The scanner module follows a modular, composable design where different
    security tools can be combined and configured based on threat models
    and performance requirements. Each component can operate independently
    or as part of a larger scanning pipeline.

Example:
    Basic scanning workflow:
    
    >>> from app.scanner.engine import start_scan_thread
    >>> from app.scanner.runtime_scanner import scan_and_respond_in_realtime
    >>> 
    >>> # Start batch scanning
    >>> start_scan_thread(run_id=1, scan_name="Security Test")
    >>> 
    >>> # Real-time scanning
    >>> result = await scan_and_respond_in_realtime("user prompt", model_config)

Notes:
    - All scanning operations are designed to be thread-safe
    - Components support both synchronous and asynchronous operation modes
    - Extensive logging and monitoring for security operations
    - Configurable through environment variables and policy files
"""