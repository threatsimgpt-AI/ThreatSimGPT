"""Dataset processors for ThreatSimGPT.

This module contains processors for different cybersecurity datasets.
"""

from .enron import EnronProcessor
from .phishtank import PhishTankProcessor
from .cert_insider import CERTInsiderProcessor
from .lanl_auth import LANLAuthProcessor
from .mitre_attack import MITREAttackProcessor

__all__ = [
    "EnronProcessor",
    "PhishTankProcessor",
    "CERTInsiderProcessor",
    "LANLAuthProcessor",
    "MITREAttackProcessor"
]
