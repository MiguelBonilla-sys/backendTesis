"""SQLAlchemy ORM models — 7 tables for phishing detector persistence."""

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from models.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="analyst", nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        Index("ix_analyses_verdict_created", "verdict", "created_at"),
        Index("ix_analyses_created", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    email_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256, never raw body
    source: Mapped[str] = mapped_column(String(20), default="extension")
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    s_risk: Mapped[float] = mapped_column(Float, nullable=False)
    s_idn: Mapped[float] = mapped_column(Float, nullable=False)
    s_llm: Mapped[float] = mapped_column(Float, nullable=False)
    s_ti: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    url_analyses: Mapped[list["URLAnalysis"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    agent_results: Mapped[list["AgentResult"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    xai_report: Mapped["XAIReport | None"] = relationship(back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    incident: Mapped["Incident | None"] = relationship(back_populates="analysis", uselist=False, cascade="all, delete-orphan")


class URLAnalysis(Base):
    __tablename__ = "url_analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain_normalized: Mapped[str] = mapped_column(String(253))
    is_punycode: Mapped[bool] = mapped_column(Boolean, default=False)
    confusables: Mapped[list] = mapped_column(JSON, default=list)
    ratio_h: Mapped[float] = mapped_column(Float, default=0.0)
    sim_v: Mapped[float] = mapped_column(Float, default=0.0)
    s_idn_local: Mapped[float] = mapped_column(Float, default=0.0)

    analysis: Mapped["Analysis"] = relationship(back_populates="url_analyses")


class AgentResult(Base):
    __tablename__ = "agent_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    agent_name: Mapped[str] = mapped_column(String(50), nullable=False)  # "IDNAgent", "LLMAgent", "FusionAgent"
    score: Mapped[float] = mapped_column(Float, nullable=False)
    raw_output: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped["Analysis"] = relationship(back_populates="agent_results")


class TICache(Base):
    """Mirrors Redis TI cache in PostgreSQL for audit trail."""
    __tablename__ = "ti_cache"
    __table_args__ = (
        Index("ix_ti_cache_domain_cached", "domain", "cached_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    s_virustotal: Mapped[float] = mapped_column(Float, default=0.0)
    s_urlscan: Mapped[float] = mapped_column(Float, default=0.0)
    s_gsb: Mapped[float] = mapped_column(Float, default=0.0)
    s_ti_aggregate: Mapped[float] = mapped_column(Float, default=0.0)
    domain_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class XAIReport(Base):
    __tablename__ = "xai_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), unique=True)
    shap_values: Mapped[dict] = mapped_column(JSON, default=dict)
    lime_values: Mapped[dict] = mapped_column(JSON, default=dict)
    top_features: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped["Analysis"] = relationship(back_populates="xai_report")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_created", "created_at"),
        Index("ix_incidents_verdict", "verdict"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), unique=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    s_risk: Mapped[float] = mapped_column(Float, nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped["Analysis"] = relationship(back_populates="incident")
