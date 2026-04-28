"""
Data models for PhishVision detection results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """Result of a logo detection and phishing analysis."""
    
    logo_detected: bool
    brand: Optional[str] = None
    similarity_score: float = 0.0
    match_count: int = 0
    confidence: str = "none"
    verdict: str = "No analysis performed"
    risk_level: RiskLevel = RiskLevel.LOW
    domain_validation: Optional[str] = None
    sender_domain: Optional[str] = None
    official_domains: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON serialization."""
        return {
            "logo_detected": self.logo_detected,
            "brand": self.brand,
            "similarity_score": round(self.similarity_score, 2),
            "match_count": self.match_count,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "risk_level": self.risk_level.value,
            "domain_validation": self.domain_validation,
            "sender_domain": self.sender_domain,
            "official_domains": self.official_domains,
            "recommendations": self.recommendations,
        }
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        status = f"[{self.risk_level.value.upper()}] {self.verdict}"
        if self.brand:
            status += f" (Detected: {self.brand} - {self.similarity_score:.1f}%)"
        return status
