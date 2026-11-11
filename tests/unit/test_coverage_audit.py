from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.detectors.base import DetectorMetadata, ScanContext
from agentsec.engine.coverage_audit import audit_scan_coverage, degraded_audit
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import (
    Applicability,
    Coverage,
    DetectorResult,
    ScanResult,
    ThreatDatabase,
)

LIMITS = DiscoveryLimits(max_file_bytes=4_000_000, max_files=1000, max_diagnostics=100)


def _metadata(not_scanned: tuple[str, ...]) -> DetectorMetadata:
    return DetectorMetadata(
        description="test detector",
        supported_inputs=("regular files",),
        campaign_ids=(),
        technique_ids=(),
        source_references=(),
        limitations=(),
        remediation_url=None,
        not_scanned=not_scanned,
    )


class StubDetector:
    """Applicable detector with configurable not_scanned metadata."""

    version = "1"

    def __init__(
        self,
        identifier: str,
        not_scanned: tuple[str, ...],
        *,
        empty_result: bool = False,
    ) -> None:
        self.id = identifier
        self.metadata = _metadata(not_scanned)
        self._empty_result = empty_result

    def applies(self, context: ScanContext) -> bool:
        return True

    def run(self, context: ScanContext) -> DetectorResult:
        coverage = (
            Coverage()
            if self._empty_result
            else Coverage(
                files_seen=len(context.files),
                files_inspected=len(context.files),
                bytes_inspected=sum(item.size for item in context.files),
            )
        )
        return DetectorResult(
            detector_id=self.id,
            applicability=Applicability.APPLICABLE,
            findings=(),
            diagnostics=(),
            coverage=coverage,
        )


class ExplodingDetector:
    id = "explode"
    version = "1"
    metadata = _metadata(("explode.outside",))

    def applies(self, context: ScanContext) -> bool:
        return True

    def run(self, context: ScanContext) -> DetectorResult:
        raise RuntimeError("boom")


@pytest.fixture
def empty_database() -> ThreatDatabase:
    return ThreatDatabase(
        version="test",
        updated="2026-08-06",
        package_versions={},
        wildcard_package_versions={},
        hashes={},
        domains=frozenset(),
        commit_indicators=(),
    )


def _checks_by_name(audit: dict[str, object]) -> dict[str, dict[str, object]]:
    checks = audit["checks"]
    assert isinstance(checks, list)
    return {check["name"]: check for check in checks}  # type: ignore[index]


def test_audit_attributes_union_and_global_overlap_per_detector(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    (tmp_path / "input.txt").write_text("evidence")
    detectors = [
        StubDetector("beta", ()),
        StubDetector("alpha", ("alpha.custom", "host.caches")),
    ]

    result = run_scan(tmp_path, detectors, empty_database, LIMITS)
    audit = result.coverage_audit

    assert audit is not None
    assert audit["scope"] == "source"
    assert audit["complete"] is True
    assert audit["exit_code"] == 0
    assert audit["detector_count"] == 2

    entries = {entry["detector_id"]: entry for entry in audit["detectors"]}
    assert set(entries) == {"alpha", "beta"}
    assert entries["alpha"]["applicability"] == "applicable"
    assert entries["alpha"]["findings"] == 0
    assert entries["alpha"]["diagnostics"] == 0
    assert entries["alpha"]["not_scanned"] == ["alpha.custom", "host.caches"]
    assert entries["alpha"]["also_declared_globally"] == ["host.caches"]
    assert entries["beta"]["not_scanned"] == []
    assert entries["beta"]["also_declared_globally"] == []

    # The audit mirrors the actual per-detector coverage on the ScanResult.
    for detector_result in result.detector_results:
        entry = entries[detector_result.detector_id]
        assert entry["not_scanned"] == sorted(set(detector_result.coverage.not_scanned))

    assert audit["not_scanned_union"] == [
        {"capability": "alpha.custom", "declared_by": ["alpha"]},
        {"capability": "host.caches", "declared_by": ["alpha"]},
    ]
    assert audit["global_overlap"] == ["host.caches"]
    assert "host.credentials" in audit["global_not_scanned"]

    checks = _checks_by_name(audit)
    assert checks["scan_complete"]["passed"] is True
    assert checks["detector_not_scanned_declared:alpha"]["passed"] is True
    beta_declared = checks["detector_not_scanned_declared:beta"]
    assert beta_declared["passed"] is False
    assert "no not-scanned capabilities" in beta_declared["reason"]
    # The empty not_scanned declaration fails a check, so the audit must not pass.
    assert audit["passed"] is False


def test_audit_flags_suspicious_empty_detector_result(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    detector = StubDetector("quiet", ("quiet.outside",), empty_result=True)

    result = run_scan(tmp_path, [detector], empty_database, LIMITS)
    audit = result.coverage_audit

    assert audit is not None
    checks = _checks_by_name(audit)
    suspicious = checks["detector_result_not_suspiciously_empty:quiet"]
    assert suspicious["passed"] is False
    assert "suspicious empty result" in suspicious["reason"]
    assert audit["passed"] is False


def test_audit_marks_detector_exception_as_incomplete_coverage(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path, [ExplodingDetector()], empty_database, LIMITS)
    audit = result.coverage_audit

    assert audit is not None
    assert audit["complete"] is False
    assert audit["exit_code"] == 2
    assert audit["passed"] is False
    checks = _checks_by_name(audit)
    scan_complete = checks["scan_complete"]
    assert scan_complete["passed"] is False
    assert "detector failed: explode: boom" in scan_complete["reason"]


def test_audit_handles_empty_detector_list(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path, [], empty_database, LIMITS)
    audit = result.coverage_audit

    assert audit is not None
    assert audit["complete"] is True
    assert audit["detector_count"] == 0
    assert audit["detectors"] == []
    assert audit["not_scanned_union"] == []
    assert audit["passed"] is True


def test_audit_degrades_when_scan_root_is_missing(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path / "missing", (), empty_database, LIMITS)
    audit = result.coverage_audit

    assert audit is not None
    assert audit["complete"] is False
    assert audit["exit_code"] == 2
    assert audit["detector_count"] == 0
    assert audit["passed"] is False
    checks = _checks_by_name(audit)
    assert checks["scan_complete"]["passed"] is False
    assert "coverage incomplete" in checks["scan_complete"]["reason"]


def test_audit_is_json_serializable(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    (tmp_path / "input.txt").write_text("evidence")
    detectors = [
        StubDetector("alpha", ("alpha.custom", "host.caches")),
        StubDetector("beta", ()),
        ExplodingDetector(),
    ]

    result = run_scan(tmp_path, detectors, empty_database, LIMITS)

    encoded = json.dumps(result.coverage_audit)
    decoded = json.loads(encoded)
    assert decoded == result.coverage_audit
    json.dumps(degraded_audit())


def test_audit_accepts_plain_scan_result_snapshot(tmp_path: Path) -> None:
    result = ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=tmp_path,
        detector_results=(),
        diagnostics=(),
        elapsed_ms=0,
    )

    assert result.coverage_audit is None
    audit = audit_scan_coverage(result)
    assert audit["detector_count"] == 0
    assert audit["passed"] is True
    json.dumps(audit)
