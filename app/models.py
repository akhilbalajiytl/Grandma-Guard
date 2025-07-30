"""GrandmaGuard Database Models Module.

This module defines the SQLAlchemy ORM models for the GrandmaGuard AI security
scanning application. It provides the database schema for storing test runs,
individual test results, and runtime security logs.

The database design supports:
    - Multi-layered security scanning with various AI safety tools
    - Hierarchical organization of test campaigns and individual results
    - Runtime monitoring and audit trail functionality
    - Comprehensive security metadata and forensic analysis

Key Models:
    - TestRun: Represents a security scanning campaign
    - TestResult: Individual test case results with multi-scanner metadata
    - RuntimeLog: Real-time security event logging for proxy operations

Database Features:
    - Proper foreign key relationships with cascade deletion
    - JSON columns for structured metadata storage
    - Timestamp tracking for audit and compliance
    - Enum constraints for data integrity
    - Scalable design supporting large-scale security testing

Dependencies:
    - SQLAlchemy: ORM framework for database operations
    - JSON: Structured data storage for complex security metadata
    - DateTime: Timestamp management for audit trails

Example:
    Create a new test run and add results:
    
    >>> from app.models import TestRun, TestResult
    >>> run = TestRun(scan_name="Security Assessment 2024")
    >>> result = TestResult(
    ...     run_id=run.id,
    ...     owasp_category="LLM01",
    ...     payload="Test prompt",
    ...     response="Model response",
    ...     status="PASS"
    ... )

Notes:
    - All models inherit from SQLAlchemy declarative base
    - Relationships are bidirectional with proper cascade behavior
    - JSON columns support complex structured data for security metadata
    - Database sessions should be managed at the application level
"""

# app/models.py
import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship, sessionmaker

Base = declarative_base()


class TestRun(Base):
    """Database model representing a security scanning campaign.
    
    A TestRun represents a complete security assessment campaign targeting
    a specific AI model or API endpoint. It serves as a container for
    multiple individual test results and tracks overall campaign metrics.
    
    Attributes:
        id (int): Primary key identifier for the test run
        scan_name (str): Human-readable name for the scanning campaign
        timestamp (datetime): UTC timestamp when the test run was created
        overall_score (float): Percentage of tests that passed (0.0-1.0)
        results (List[TestResult]): Collection of individual test results
        
    Relationships:
        - One-to-many with TestResult (cascade delete)
        
    Cascade Behavior:
        - Deleting a TestRun automatically deletes all associated TestResults
        
    Example:
        >>> run = TestRun(scan_name="GPT-4 Security Assessment")
        >>> print(f"Run {run.id}: {run.scan_name} scored {run.overall_score:.2%}")
        
    Notes:
        - Overall score is calculated from final test results
        - Timestamp uses UTC for consistent cross-timezone operations
        - Scan names should be descriptive for easy identification
    """
    __tablename__ = "test_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Rename the column in the model to match what the code now uses.
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)

    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    results: Mapped[list["TestResult"]] = relationship(
        "TestResult", back_populates="run", cascade="all, delete-orphan"
    )


class TestResult(Base):
    """Database model for individual AI security test results.
    
    Represents the outcome of a single security test within a larger scanning
    campaign. Each test result contains the original prompt, model response,
    and assessments from multiple security scanning tools.
    
    Multi-Scanner Architecture:
        The model supports results from multiple scanning tools:
        - Garak: Comprehensive AI red-teaming framework
        - LlamaGuard: Meta's AI safety classifier
        - AI Judge: LLM-based content assessment
        
    Attributes:
        id (int): Primary key identifier
        run_id (int): Foreign key to parent TestRun
        owasp_category (str): OWASP AI security category (e.g., "LLM01")
        payload (str): Original test prompt/input
        response (str): AI model's response to the test prompt
        judge_status (str, optional): LLM-as-a-Judge assessment result
        llama_guard_status (dict, optional): LlamaGuard classification results
        garak_status (str, optional): Garak scanning tool result
        status (str): Final consolidated test result status
        
    Status Values:
        - PASS: Test passed security checks
        - FAIL: Test failed, potential security issue detected
        - PENDING_REVIEW: Requires human review
        - ERROR: Technical error during testing
        
    OWASP Categories:
        Based on OWASP Top 10 for LLM Applications:
        - LLM01: Prompt Injection
        - LLM02: Insecure Output Handling
        - LLM03: Training Data Poisoning
        - etc.
        
    Relationships:
        - Many-to-one with TestRun
        
    Example:
        >>> result = TestResult(
        ...     run_id=1,
        ...     owasp_category="LLM01",
        ...     payload="Ignore previous instructions...",
        ...     response="I cannot help with that.",
        ...     status="PASS"
        ... )
        
    Notes:
        - Status field represents the final consolidated assessment
        - JSON columns store structured metadata from scanning tools
        - Text fields support large prompts and responses
        - Default status is PENDING_REVIEW for safety
    """
    __tablename__ = "test_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("test_runs.id"), nullable=False
    )
    owasp_category: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False)

    # --- MODIFIED COLUMNS ---
    # The result from our simple keyword/regex check
    # baseline_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # The result from the LLM-as-a-Judge (we can repurpose this or keep it)
    judge_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    llama_guard_status: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # --- NEW GARAK COLUMN ---
    garak_status: Mapped[str | None] = mapped_column(
        String(50), nullable=True, default="NOT_RUN"
    )
    # This will be the final, definitive status for reporting.
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="PENDING_REVIEW"
    )

    run: Mapped["TestRun"] = relationship("TestRun", back_populates="results")


def get_db_session(db_url: str):
    """Create a new database session for the given database URL.
    
    Utility function to create a SQLAlchemy session with automatic
    table creation. Primarily used for testing and standalone scripts.
    
    Args:
        db_url (str): SQLAlchemy database connection URL
        
    Returns:
        Session: Configured SQLAlchemy session instance
        
    Side Effects:
        - Creates all database tables if they don't exist
        - Establishes database connection
        
    Example:
        >>> session = get_db_session("sqlite:///test.db")
        >>> runs = session.query(TestRun).all()
        
    Notes:
        - Automatically creates tables using metadata
        - Returns a bound session ready for use
        - Primarily for testing; production uses scoped sessions
    """
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


class RuntimeLog(Base):
    """Database model for runtime security monitoring and audit logging.
    
    Captures real-time security events from the proxy endpoint and other
    runtime scanning activities. Provides audit trail for compliance
    and forensic analysis of AI safety incidents.
    
    Attributes:
        id (int): Primary key identifier
        timestamp (datetime): UTC timestamp when the event occurred
        user_prompt (str): Original user input that triggered scanning
        llm_response (str): AI model's response after security filtering
        decision (str): Security decision made by the system
        model_identifier (str): Model that processed the request
        forensic_status (str): Status of forensic analysis process
        forensic_risk_profile (dict, optional): Structured risk assessment data
        
    Decision Values:
        - ALLOW: Request passed security checks
        - BLOCK: Request blocked due to security concerns
        - WARN: Request allowed with warnings
        - ERROR: Technical error during processing
        
    Forensic Status Values:
        - PENDING: Forensic analysis not yet started
        - RUNNING: Analysis in progress
        - COMPLETE: Analysis finished
        - ERROR: Analysis failed
        
    Risk Profile Structure:
        JSON object containing detailed security assessment:
        {
            "threat_level": "HIGH|MEDIUM|LOW",
            "categories": ["prompt_injection", "data_exfiltration"],
            "confidence": 0.85,
            "mitigations": ["content_filter", "response_sanitization"]
        }
        
    Use Cases:
        - Security incident investigation
        - Compliance reporting and audit trails
        - Performance monitoring of security controls
        - Threat intelligence and pattern analysis
        
    Example:
        >>> log = RuntimeLog(
        ...     user_prompt="Tell me how to hack...",
        ...     llm_response="I cannot provide that information.",
        ...     decision="BLOCK",
        ...     model_identifier="gpt-3.5-turbo"
        ... )
        
    Notes:
        - All timestamps use UTC for consistent logging
        - Large text fields support complex prompts and responses
        - JSON profile enables structured security metadata
        - Enum constraints ensure data integrity for status fields
    """
    __tablename__ = "runtime_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    user_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    llm_response: Mapped[str] = mapped_column(Text, nullable=False)

    # REMOVE the redundant triage_risk_profile column
    # triage_risk_profile: Mapped[dict | None] = mapped_column(JSON)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    model_identifier: Mapped[str] = mapped_column(String(255))

    forensic_status: Mapped[str] = mapped_column(
        Enum("PENDING", "RUNNING", "COMPLETE", "ERROR", name="forensic_status_enum"),
        default="PENDING",
        nullable=False,
    )
    # This single column will now hold the full structured profile
    forensic_risk_profile: Mapped[dict | None] = mapped_column(JSON)
