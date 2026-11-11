"""Pure-function audit of the scan coverage contract.

The audit consumes a :class:`~agentsec.models.ScanResult` (or an equivalent
plain-data snapshot) and produces a JSON-serializable mapping that describes
what the scan did and did not cover:

* the scan scope, completeness, exit code, and detector count;
* per-detector applicability, finding/diagnostic counts, declared
  ``not_scanned`` capabilities, and which of those are already declared
  globally (and therefore need no repeated attention);
* the cross-detector union of not-scanned capabilities with the detectors
  that declared each one;
* an ordered list of named checks with pass/fail and a human-readable
  reason for every failure.

The returned object contains only strings, numbers, booleans, lists, dicts,
and ``None`` — no ``Path`` objects, detector instances, or function
references — so ``json.dumps`` always succeeds on it.
"""

from __future__ import annotations

from typing import Any

from agentsec.models import Applicability, DiagnosticKind, ScanResult
from agentsec.scopes import ScanScope


def audit_scan_coverage(result: ScanResult) -> dict[str, Any]:
    """Audit the coverage contract of one scan result.

    The function is pure and total: it never raises for a well-formed
    ``ScanResult`` and never mutates its input.
    """
    global_not_scanned = sorted(set(result.global_not_scanned))
    global_set = set(global_not_scanned)

    error_messages = sorted(
        diagnostic.message
        for diagnostic in (
            *result.diagnostics,
            *(
                detector_diagnostic
                for detector_result in result.detector_results
                for detector_diagnostic in detector_result.diagnostics
            ),
        )
        if diagnostic.kind is DiagnosticKind.ERROR
    )
    scan_complete = result.complete and not error_messages

    checks: list[dict[str, Any]] = [
        {
            "name": "scan_complete",
            "passed": scan_complete,
            "reason": (
                None
                if scan_complete
                else "coverage incomplete: scan reported error diagnostics: "
                + ("; ".join(error_messages) or "scan marked incomplete")
            ),
        }
    ]

    detectors: list[dict[str, Any]] = []
    declared_by: dict[str, list[str]] = {}
    for detector_result in result.detector_results:
        detector_id = detector_result.detector_id
        not_scanned = sorted(set(detector_result.coverage.not_scanned))
        for capability in not_scanned:
            declared_by.setdefault(capability, []).append(detector_id)
        detectors.append(
            {
                "detector_id": detector_id,
                "applicability": detector_result.applicability.value,
                "findings": len(detector_result.findings),
                "diagnostics": len(detector_result.diagnostics),
                "not_scanned": not_scanned,
                "also_declared_globally": [
                    capability for capability in not_scanned if capability in global_set
                ],
            }
        )
        checks.append(
            {
                "name": f"detector_not_scanned_declared:{detector_id}",
                "passed": bool(not_scanned),
                "reason": (
                    None
                    if not_scanned
                    else f"detector '{detector_id}' declared no not-scanned "
                    "capabilities; do not treat it as full coverage"
                ),
            }
        )
        coverage = detector_result.coverage
        suspicious = (
            detector_result.applicability is Applicability.APPLICABLE
            and not detector_result.findings
            and not detector_result.diagnostics
            and coverage.files_seen == 0
            and coverage.files_inspected == 0
            and coverage.bytes_inspected == 0
        )
        checks.append(
            {
                "name": f"detector_result_not_suspiciously_empty:{detector_id}",
                "passed": not suspicious,
                "reason": (
                    f"detector '{detector_id}' returned a suspicious empty result "
                    "(applicable with no findings, no diagnostics, and zero "
                    "coverage counts); manual review recommended"
                    if suspicious
                    else None
                ),
            }
        )

    not_scanned_union = [
        {"capability": capability, "declared_by": sorted(detector_ids)}
        for capability, detector_ids in sorted(declared_by.items())
    ]

    return {
        "scope": result.scope.value,
        "complete": result.complete,
        "exit_code": result.exit_code(),
        "detector_count": len(result.detector_results),
        "detectors": detectors,
        "global_not_scanned": global_not_scanned,
        "global_overlap": sorted(global_set & set(declared_by)),
        "not_scanned_union": not_scanned_union,
        "checks": checks,
        "passed": all(check["passed"] for check in checks),
    }


def degraded_audit(scope: ScanScope = ScanScope.SOURCE) -> dict[str, Any]:
    """Return a degraded audit for scans that produced no detector results.

    Used when a scan cannot be audited from a real result (for example when
    the scan root could not be resolved): coverage is reported as incomplete
    and the audit never passes.
    """
    return {
        "scope": scope.value,
        "complete": False,
        "exit_code": 2,
        "detector_count": 0,
        "detectors": [],
        "global_not_scanned": [],
        "global_overlap": [],
        "not_scanned_union": [],
        "checks": [
            {
                "name": "scan_complete",
                "passed": False,
                "reason": "coverage incomplete: scan did not produce detector results",
            }
        ],
        "passed": False,
    }
