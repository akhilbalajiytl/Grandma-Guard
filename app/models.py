# app/models.py
import datetime

from sqlalchemy import (
    DateTime,
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
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# --- Model for Runtime Security Logs ---
class RuntimeLog(Base):
    __tablename__ = "runtime_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    user_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    llm_response: Mapped[str] = mapped_column(Text, nullable=False)

    # The outcome of our real-time scan
    garak_status: Mapped[str | None] = mapped_column(String(50))
    judge_status: Mapped[str | None] = mapped_column(String(50))

    # The final decision made by the firewall
    decision: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # e.g., "ALLOWED", "BLOCKED"

    # The model that was called
    model_identifier: Mapped[str] = mapped_column(String(255))
