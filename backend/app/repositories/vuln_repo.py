"""Vulnerability persistence — delegates to ScanRepository for shared queries."""

from app.repositories.scan_repo import ScanRepository


class VulnerabilityRepository(ScanRepository):
    """Convenience alias — inherits all vulnerability methods from ScanRepository."""

    pass
