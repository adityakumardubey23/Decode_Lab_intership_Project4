from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str
    details: str
    recommendation: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    generated_at: str
    hostname: str
    operating_system: str
    results: list[CheckResult]

    @classmethod
    def create(cls, hostname: str, operating_system: str,
               results: list[CheckResult]) -> "AuditReport":
        return cls(
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            hostname=hostname,
            operating_system=operating_system,
            results=results,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "operating_system": self.operating_system,
            "results": [result.to_dict() for result in self.results],
        }
