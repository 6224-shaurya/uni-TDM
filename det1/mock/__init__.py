"""Mock detector implementations simulating T-a through T-f model behaviors."""

from det1.mock.mock_ddos import MockDDoSDetector
from det1.mock.mock_beaconing import MockBeaconingDetector
from det1.mock.mock_dga import MockDGADetector
from det1.mock.mock_encrypted_malware import MockEncryptedMalwareDetector
from det1.mock.mock_recon import MockReconDetector
from det1.mock.mock_exfiltration import MockExfiltrationDetector

__all__ = [
    "MockDDoSDetector",
    "MockBeaconingDetector",
    "MockDGADetector",
    "MockEncryptedMalwareDetector",
    "MockReconDetector",
    "MockExfiltrationDetector",
]
