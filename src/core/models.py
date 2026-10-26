"""
III85III OBSIDIAN — Core Data Models
Strict anti-fabrication models for security findings, scan sessions, and system telemetry.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    TENTATIVE = "TENTATIVE"


class FindingStatus(str, Enum):
    OBSERVED = "OBSERVED"
    POTENTIAL = "POTENTIAL"
    SCANNER_REPORTED = "SCANNER_REPORTED"
    VALIDATED = "VALIDATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_VERIFIED = "NOT_VERIFIED"
    FAILED_COLLECTION = "FAILED_COLLECTION"


@dataclass
class Finding:
    title: str
    description: str
    source_tool: str
    target: str
    severity: FindingSeverity
    severity_source: str
    confidence: FindingConfidence
    confidence_justification: str
    evidence_raw: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_version: str = "Unknown"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: FindingStatus = FindingStatus.SCANNER_REPORTED
    evidence_summary: str = ""
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_component: Optional[str] = None
    remediation: str = "Review configuration and apply vendor patches."
    scan_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "source_tool": self.source_tool,
            "tool_version": self.tool_version,
            "target": self.target,
            "timestamp": self.timestamp,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else str(self.severity),
            "severity_source": self.severity_source,
            "confidence": self.confidence.value if isinstance(self.confidence, FindingConfidence) else str(self.confidence),
            "confidence_justification": self.confidence_justification,
            "status": self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "evidence_raw": self.evidence_raw,
            "evidence_summary": self.evidence_summary,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "scan_id": self.scan_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data.get("title", "Untitled Finding"),
            description=data.get("description", ""),
            source_tool=data.get("source_tool", "Unknown"),
            tool_version=data.get("tool_version", "Unknown"),
            target=data.get("target", "N/A"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            severity=FindingSeverity(data.get("severity", FindingSeverity.INFO.value)),
            severity_source=data.get("severity_source", "Manual"),
            confidence=FindingConfidence(data.get("confidence", FindingConfidence.MEDIUM.value)),
            confidence_justification=data.get("confidence_justification", ""),
            status=FindingStatus(data.get("status", FindingStatus.SCANNER_REPORTED.value)),
            evidence_raw=data.get("evidence_raw", ""),
            evidence_summary=data.get("evidence_summary", ""),
            cve_id=data.get("cve_id"),
            cwe_id=data.get("cwe_id"),
            affected_component=data.get("affected_component"),
            remediation=data.get("remediation", ""),
            scan_id=data.get("scan_id"),
        )


@dataclass
class ScanRun:
    tool_name: str
    target: str
    raw_command: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: Optional[str] = None
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, CANCELLED
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    findings_count: int = 0
    request_count: int = 0
    duration_ms: int = 0
    response_status: Optional[int] = None
    completion_reason: Optional[str] = None
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    parent_scan_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "target": self.target,
            "raw_command": self.raw_command,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "findings_count": self.findings_count,
            "request_count": self.request_count,
            "duration_ms": self.duration_ms,
            "response_status": self.response_status,
            "completion_reason": self.completion_reason,
            "execution_log": self.execution_log,
            "parent_scan_id": self.parent_scan_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanRun:
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            tool_name=data.get("tool_name", "Unknown"),
            target=data.get("target", "Unknown"),
            raw_command=data.get("raw_command", ""),
            start_time=data.get("start_time", datetime.now(timezone.utc).isoformat()),
            end_time=data.get("end_time"),
            status=data.get("status", "COMPLETED"),
            exit_code=data.get("exit_code"),
            error_message=data.get("error_message"),
            findings_count=data.get("findings_count", 0),
            request_count=data.get("request_count", 0),
            duration_ms=data.get("duration_ms", 0),
            response_status=data.get("response_status"),
            completion_reason=data.get("completion_reason"),
            execution_log=data.get("execution_log", []) or [],
            parent_scan_id=data.get("parent_scan_id"),
        )


@dataclass
class ToolHealthInfo:
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None
    status_message: str = "Ready"
    availability_status: str = ""
    last_checked: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not self.availability_status:
            # Presence alone is not proof that an executable/API works or that
            # its version was checked. Callers must opt into the verified state.
            self.availability_status = "VERSION_CHECK_FAILED" if self.installed else "MISSING"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "installed": self.installed,
            "version": self.version,
            "path": self.path,
            "status_message": self.status_message,
            "availability_status": self.availability_status,
            "last_checked": self.last_checked,
        }


@dataclass
class DefenderThreat:
    detection_id: str
    threat_name: str
    threat_id: int
    severity: str
    initial_detection_time: str
    remediation_time: Optional[str]
    process_name: Optional[str]
    resources: List[str]
    action_success: bool
    status_description: str
