"""
III85III OBSIDIAN — SQLite Persistence Layer
Thread-safe, parameterized, relational persistence for scans, findings, and events.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.config import DB_PATH
from src.core.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ScanRun,
    ToolHealthInfo,
)


class DatabaseManager:
    """Thread-safe SQLite manager for OBSIDIAN."""

    _instance: Optional[DatabaseManager] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = str(db_path or DB_PATH)
        self._local = threading.local()
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path] = None) -> DatabaseManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = DatabaseManager(db_path)
            return cls._instance

    def close(self) -> None:
        """Close the thread-local database connection if open."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    raw_command TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    error_message TEXT,
                    findings_count INTEGER DEFAULT 0,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    response_status INTEGER,
                    completion_reason TEXT,
                    execution_log_json TEXT NOT NULL DEFAULT '[]',
                    parent_scan_id TEXT
                );
                """
            )
            scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
            for column, definition in (
                ("request_count", "INTEGER NOT NULL DEFAULT 0"),
                ("duration_ms", "INTEGER NOT NULL DEFAULT 0"),
                ("response_status", "INTEGER"),
                ("completion_reason", "TEXT"),
                ("execution_log_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("parent_scan_id", "TEXT"),
            ):
                if column not in scan_columns:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    source_tool TEXT NOT NULL,
                    tool_version TEXT,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    severity_source TEXT,
                    confidence TEXT NOT NULL,
                    confidence_justification TEXT,
                    status TEXT NOT NULL,
                    evidence_raw TEXT,
                    evidence_summary TEXT,
                    cve_id TEXT,
                    cwe_id TEXT,
                    affected_component TEXT,
                    remediation TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_health (
                    name TEXT PRIMARY KEY,
                    installed INTEGER NOT NULL,
                    version TEXT,
                    path TEXT,
                    status_message TEXT,
                    last_checked TEXT NOT NULL,
                    availability_status TEXT NOT NULL DEFAULT 'MISSING'
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_parent ON scans(parent_scan_id)")
            health_columns = {row[1] for row in conn.execute("PRAGMA table_info(tool_health)").fetchall()}
            if "availability_status" not in health_columns:
                conn.execute("ALTER TABLE tool_health ADD COLUMN availability_status TEXT NOT NULL DEFAULT 'MISSING'")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT
                );
                """
            )

    # ---------------- Scans ----------------
    def save_scan(self, scan: ScanRun) -> None:
        conn = self._get_connection()
        with conn:
            self._store_scan(conn, scan)

    @staticmethod
    def _store_scan(conn: sqlite3.Connection, scan: ScanRun) -> None:
        conn.execute(
            """
            INSERT INTO scans (
                id, tool_name, target, raw_command, start_time, end_time,
                status, exit_code, error_message, findings_count,
                request_count, duration_ms, response_status, completion_reason,
                execution_log_json, parent_scan_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                tool_name=excluded.tool_name, target=excluded.target,
                raw_command=excluded.raw_command, start_time=excluded.start_time,
                end_time=excluded.end_time, status=excluded.status,
                exit_code=excluded.exit_code, error_message=excluded.error_message,
                findings_count=excluded.findings_count, request_count=excluded.request_count,
                duration_ms=excluded.duration_ms, response_status=excluded.response_status,
                completion_reason=excluded.completion_reason,
                execution_log_json=excluded.execution_log_json,
                parent_scan_id=excluded.parent_scan_id;
            """,
            (
                scan.id,
                scan.tool_name,
                scan.target,
                scan.raw_command,
                scan.start_time,
                scan.end_time,
                scan.status,
                scan.exit_code,
                scan.error_message,
                scan.findings_count,
                scan.request_count,
                scan.duration_ms,
                scan.response_status,
                scan.completion_reason,
                json.dumps(scan.execution_log, ensure_ascii=False),
                scan.parent_scan_id,
            ),
        )

    def save_import(self, scan: ScanRun, findings: List[Finding]) -> None:
        """Commit one imported assessment and all its findings, or none of them."""
        if any(finding.scan_id != scan.id for finding in findings):
            raise ValueError("Imported findings must belong to their assessment.")
        conn = self._get_connection()
        with conn:
            self._store_scan(conn, scan)
            for finding in findings:
                self._store_finding(conn, finding)
            conn.execute("UPDATE scans SET findings_count = (SELECT COUNT(*) FROM findings WHERE scan_id = ?) WHERE id = ?",
                         (scan.id, scan.id))

    def get_scan(self, scan_id: str) -> Optional[ScanRun]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        data["execution_log"] = json.loads(data.pop("execution_log_json", "[]") or "[]")
        return ScanRun.from_dict(data)

    def list_scans(self, limit: int = 50, root_only: bool = False) -> List[ScanRun]:
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM scans " + ("WHERE parent_scan_id IS NULL " if root_only else "")
            + "ORDER BY start_time DESC LIMIT ?;", (limit,)
        )
        scans = []
        for row in cursor.fetchall():
            data = dict(row)
            data["execution_log"] = json.loads(data.pop("execution_log_json", "[]") or "[]")
            scans.append(ScanRun.from_dict(data))
        return scans

    # ---------------- Findings ----------------
    def save_finding(self, finding: Finding) -> None:
        conn = self._get_connection()
        with conn:
            self._store_finding(conn, finding)

    @staticmethod
    def _store_finding(conn: sqlite3.Connection, finding: Finding) -> None:
        from src.core.privacy import sanitize_data
        finding = Finding.from_dict(sanitize_data(finding.to_dict()))
        conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, scan_id, title, description, source_tool, tool_version,
                target, timestamp, severity, severity_source, confidence,
                confidence_justification, status, evidence_raw, evidence_summary,
                cve_id, cwe_id, affected_component, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                finding.id,
                finding.scan_id,
                finding.title,
                finding.description,
                finding.source_tool,
                finding.tool_version,
                finding.target,
                finding.timestamp,
                finding.severity.value if isinstance(finding.severity, FindingSeverity) else str(finding.severity),
                finding.severity_source,
                finding.confidence.value if isinstance(finding.confidence, FindingConfidence) else str(finding.confidence),
                finding.confidence_justification,
                finding.status.value if isinstance(finding.status, FindingStatus) else str(finding.status),
                finding.evidence_raw,
                finding.evidence_summary,
                finding.cve_id,
                finding.cwe_id,
                finding.affected_component,
                finding.remediation,
            ),
        )
        # Update findings count on parent scan
        if finding.scan_id:
            conn.execute(
                """
                UPDATE scans SET findings_count = (
                    SELECT COUNT(*) FROM findings WHERE scan_id = ?
                ) WHERE id = ?;
                """,
                (finding.scan_id, finding.scan_id),
            )

    def update_finding_status(self, finding_id: str, new_status: FindingStatus) -> bool:
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?;",
                (new_status.value, finding_id),
            )
            return cursor.rowcount > 0

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM findings WHERE id = ?;", (finding_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return Finding.from_dict(dict(row))

    def list_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: Optional[int] = 200,
    ) -> List[Finding]:
        conn = self._get_connection()
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if scan_id:
            query += " AND (scan_id = ? OR scan_id IN (SELECT id FROM scans WHERE parent_scan_id = ?))"
            params.extend([scan_id, scan_id])
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC, id"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor = conn.execute(query, tuple(params))
        return [Finding.from_dict(dict(row)) for row in cursor.fetchall()]

    def get_findings_summary(self) -> Dict[str, int]:
        conn = self._get_connection()
        summary = {
            "TOTAL": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "VALIDATED": 0,
            "FALSE_POSITIVE": 0,
        }
        cursor = conn.execute("SELECT severity, COUNT(*) as c FROM findings GROUP BY severity;")
        for row in cursor.fetchall():
            sev = row["severity"]
            if sev in summary:
                summary[sev] = row["c"]
            summary["TOTAL"] += row["c"]

        cursor = conn.execute("SELECT status, COUNT(*) as c FROM findings GROUP BY status;")
        for row in cursor.fetchall():
            stat = row["status"]
            if stat in summary:
                summary[stat] = row["c"]

        return summary

    # ---------------- Tool Health ----------------
    def save_tool_health(self, health: ToolHealthInfo) -> None:
        self.save_tool_health_batch([health])

    def save_tool_health_batch(self, records: List[ToolHealthInfo]) -> None:
        conn = self._get_connection()
        with conn:
            for health in records:
                self._store_tool_health(conn, health)

    @staticmethod
    def _store_tool_health(conn, health: ToolHealthInfo) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO tool_health (
                name, installed, version, path, status_message, last_checked,
                availability_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                health.name,
                1 if health.installed else 0,
                health.version,
                health.path,
                health.status_message,
                health.last_checked,
                health.availability_status,
            ),
        )

    def list_tool_health(self) -> List[ToolHealthInfo]:
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM tool_health ORDER BY name ASC;")
        results = []
        for row in cursor.fetchall():
            results.append(
                ToolHealthInfo(
                    name=row["name"],
                    installed=bool(row["installed"]),
                    version=row["version"],
                    path=row["path"],
                    status_message=row["status_message"],
                    availability_status=row["availability_status"] if "availability_status" in row.keys() else "",
                    last_checked=row["last_checked"],
                )
            )
        return results

    # ---------------- System Events ----------------
    def save_system_event(
        self,
        event_type: str,
        source: str,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO system_events (timestamp, event_type, source, severity, message, details_json)
                VALUES (datetime('now'), ?, ?, ?, ?, ?);
                """,
                (
                    event_type,
                    source,
                    severity,
                    message,
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )

    def list_system_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM system_events ORDER BY id DESC LIMIT ?;", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
