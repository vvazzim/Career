"""
PhishVision - Computer Vision Phishing Detection Library
"""

__version__ = "0.1.0"
__author__ = "Security Engineering Team"

from phish_vision.core import LogoDetectionEngine
from phish_vision.models import DetectionResult, RiskLevel
from phish_vision.database import BrandDatabase

__all__ = [
    "LogoDetectionEngine",
    "DetectionResult",
    "RiskLevel",
    "BrandDatabase",
]
