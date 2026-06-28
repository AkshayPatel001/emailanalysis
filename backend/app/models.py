"""
SQLAlchemy ORM models for the Email Analysis Tool.
Tracks analysis cases, results, IOCs, and search history.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    DateTime,
    Boolean,
    JSON,
    ForeignKey,
    Index,
    Uuid,
)

from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return uuid.uuid4()


class AnalysisCase(Base):
    """
    Top-level case for an email analysis.
    Each upload/analysis creates one case.
    """
    __tablename__ = "analysis_cases"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    case_number = Column(String(32), unique=True, nullable=False, index=True)
    status = Column(
        String(20),
        nullable=False,
        default="new",  # new, in_progress, completed, escalated, closed
    )
    severity = Column(
        String(20),
        nullable=True,  # critical, high, medium, low, safe
    )
    verdict = Column(
        String(20),
        nullable=True,  # clean, suspicious, malicious
    )
    risk_score = Column(Float, nullable=True)

    # Email metadata
    email_subject = Column(Text, nullable=True)
    email_sender = Column(String(512), nullable=True)
    email_recipient = Column(String(512), nullable=True)
    email_date = Column(DateTime(timezone=True), nullable=True)
    email_message_id = Column(String(512), nullable=True)

    # Analyst fields
    analyst_notes = Column(Text, nullable=True)
    assigned_analyst = Column(String(256), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    result = relationship("AnalysisResult", back_populates="case", uselist=False, cascade="all, delete-orphan")
    iocs = relationship("IOCEntry", back_populates="case", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_case_status", "status"),
        Index("idx_case_severity", "severity"),
        Index("idx_case_created", "created_at"),
    )

    def __repr__(self):
        return f"<AnalysisCase {self.case_number} [{self.status}]>"


class AnalysisResult(Base):
    """
    Stores the full JSON analysis result for a case.
    One-to-one with AnalysisCase.
    """
    __tablename__ = "analysis_results"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    case_id = Column(
        Uuid,
        ForeignKey("analysis_cases.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Raw parsed email data
    email_metadata = Column(JSON, nullable=True)     # sender, recipients, headers, etc.
    raw_headers = Column(Text, nullable=True)

    # Analysis results by engine
    header_analysis = Column(JSON, nullable=True)     # SPF/DKIM/DMARC findings
    phishing_analysis = Column(JSON, nullable=True)   # phishing indicators
    url_analysis = Column(JSON, nullable=True)        # URL findings
    attachment_analysis = Column(JSON, nullable=True)  # attachment findings
    ioc_summary = Column(JSON, nullable=True)         # extracted IOCs
    risk_scoring = Column(JSON, nullable=True)        # scoring breakdown
    mitre_mapping = Column(JSON, nullable=True)       # MITRE ATT&CK techniques
    yara_analysis = Column(JSON, nullable=True)       # Custom YARA rule hits

    # Recommended actions
    recommended_actions = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationship
    case = relationship("AnalysisCase", back_populates="result")

    def __repr__(self):
        return f"<AnalysisResult case={self.case_id}>"


class IOCEntry(Base):
    """
    Individual Indicator of Compromise extracted from an analysis.
    """
    __tablename__ = "ioc_entries"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    case_id = Column(
        Uuid,
        ForeignKey("analysis_cases.id", ondelete="CASCADE"),
        nullable=False,
    )

    ioc_type = Column(
        String(20),
        nullable=False,  # ip, domain, url, hash_md5, hash_sha1, hash_sha256, email
    )
    ioc_value = Column(Text, nullable=False)
    defanged_value = Column(Text, nullable=True)   # Safe display version

    # Threat intel enrichment
    reputation = Column(String(20), nullable=True)   # clean, suspicious, malicious, unknown
    threat_category = Column(String(256), nullable=True)
    confidence_score = Column(Float, nullable=True)
    source = Column(String(64), nullable=True)       # virustotal, abuseipdb, etc.
    enrichment_data = Column(JSON, nullable=True)    # raw API response

    is_enriched = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationship
    case = relationship("AnalysisCase", back_populates="iocs")

    __table_args__ = (
        Index("idx_ioc_type", "ioc_type"),
        Index("idx_ioc_value", "ioc_value"),
        Index("idx_ioc_case", "case_id"),
    )

    def __repr__(self):
        return f"<IOCEntry {self.ioc_type}={self.ioc_value[:40]}>"


class SearchHistory(Base):
    """
    Tracks analyst search and analysis history.
    """
    __tablename__ = "search_history"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    search_type = Column(String(32), nullable=False)   # analysis, ioc_lookup, report
    query = Column(Text, nullable=True)
    case_id = Column(Uuid, nullable=True)
    result_summary = Column(Text, nullable=True)
    analyst = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("idx_search_created", "created_at"),
    )

    def __repr__(self):
        return f"<SearchHistory {self.search_type} @ {self.created_at}>"


class YaraRule(Base):
    """
    Custom YARA rules for threat hunting.
    """
    __tablename__ = "yara_rules"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    rule_name = Column(String(128), unique=True, nullable=False, index=True)
    rule_content = Column(Text, nullable=False)
    author = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    def __repr__(self):
        return f"<YaraRule {self.rule_name} active={self.is_active}>"


class RemediationAction(Base):
    """
    Tracks automated SOAR remediation actions (e.g., deleting emails via MS Graph).
    """
    __tablename__ = "remediation_actions"

    id = Column(Uuid, primary_key=True, default=gen_uuid)
    case_id = Column(Uuid, ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(32), nullable=False)  # delete, quarantine
    status = Column(String(32), default="pending")    # pending, in_progress, completed, failed
    affected_mailboxes = Column(Integer, default=0)
    log = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    case = relationship("AnalysisCase")

    def __repr__(self):
        return f"<RemediationAction {self.action_type} status={self.status}>"

