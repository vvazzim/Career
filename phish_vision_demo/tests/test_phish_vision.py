"""
Unit tests for PhishVision package.
"""

import pytest
from pathlib import Path
import numpy as np
import cv2

from phish_vision import LogoDetectionEngine, DetectionResult, RiskLevel, BrandDatabase


class TestBrandDatabase:
    """Tests for BrandDatabase class."""
    
    def test_default_brands_loaded(self):
        """Test that default brands are loaded on initialization."""
        db = BrandDatabase()
        brands = db.list_brands()
        assert len(brands) > 0
        assert "microsoft" in brands
        assert "paypal" in brands
    
    def test_get_official_domains(self):
        """Test retrieving official domains for a brand."""
        db = BrandDatabase()
        domains = db.get_official_domains("microsoft")
        assert "microsoft.com" in domains
        assert "office.com" in domains
    
    def test_is_official_domain_true(self):
        """Test domain validation returns True for official domains."""
        db = BrandDatabase()
        assert db.is_official_domain("microsoft", "microsoft.com") is True
        assert db.is_official_domain("microsoft", "outlook.microsoft.com") is True
    
    def test_is_official_domain_false(self):
        """Test domain validation returns False for unofficial domains."""
        db = BrandDatabase()
        assert db.is_official_domain("microsoft", "fake-microsoft.com") is False
        assert db.is_official_domain("microsoft", "ms-verify.net") is False
    
    def test_add_custom_brand(self):
        """Test adding a custom brand to the database."""
        db = BrandDatabase()
        db.add_custom_brand(
            brand_key="testbrand",
            domains=["testbrand.com"],
            logo_file="test.png",
            display_name="Test Brand"
        )
        assert "testbrand" in db.list_brands()
        assert db.get_display_name("testbrand") == "Test Brand"


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""
    
    def test_to_dict_conversion(self):
        """Test converting result to dictionary."""
        result = DetectionResult(
            logo_detected=True,
            brand="Microsoft",
            similarity_score=92.5,
            match_count=150,
            confidence="high",
            verdict="High Risk Phishing",
            risk_level=RiskLevel.CRITICAL
        )
        
        result_dict = result.to_dict()
        assert result_dict["logo_detected"] is True
        assert result_dict["brand"] == "Microsoft"
        assert result_dict["similarity_score"] == 92.5
        assert result_dict["risk_level"] == "critical"
    
    def test_string_representation(self):
        """Test string representation of result."""
        result = DetectionResult(
            logo_detected=True,
            brand="PayPal",
            similarity_score=85.0,
            verdict="High Risk Phishing",
            risk_level=RiskLevel.CRITICAL
        )
        
        result_str = str(result)
        assert "CRITICAL" in result_str
        assert "PayPal" in result_str


class TestLogoDetectionEngine:
    """Tests for LogoDetectionEngine class."""
    
    def test_engine_initialization(self):
        """Test engine initializes without errors."""
        engine = LogoDetectionEngine()
        assert engine.sift is not None
        assert engine.similarity_threshold == 80.0
    
    def test_custom_threshold(self):
        """Test setting custom similarity threshold."""
        engine = LogoDetectionEngine(similarity_threshold=90.0)
        assert engine.similarity_threshold == 90.0
    
    def test_list_available_brands(self):
        """Test listing available brands."""
        engine = LogoDetectionEngine()
        brands = engine.list_available_brands()
        assert isinstance(brands, list)
        if brands:
            assert "key" in brands[0]
            assert "name" in brands[0]
    
    def test_analyze_nonexistent_image(self):
        """Test analyzing a non-existent image file."""
        engine = LogoDetectionEngine()
        result = engine.analyze_image(image_path="nonexistent_file.png")
        
        assert result.logo_detected is False
        assert "Failed to load image" in result.verdict
        assert result.risk_level == RiskLevel.LOW
    
    def test_extract_domain(self):
        """Test domain extraction from email addresses."""
        engine = LogoDetectionEngine()
        
        # Test valid emails
        assert engine._extract_domain("user@microsoft.com") == "microsoft.com"
        assert engine._extract_domain("admin@sub.paypal.com") == "sub.paypal.com"
        
        # Test edge cases
        assert engine._extract_domain("") is None
        assert engine._extract_domain("invalid-email") is None


class TestIntegration:
    """Integration tests with sample images."""
    
    def test_full_workflow_with_placeholder(self, tmp_path):
        """Test full detection workflow with a placeholder image."""
        # Create a simple test image
        test_image = tmp_path / "test.png"
        image_data = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        cv2.imwrite(str(test_image), image_data)
        
        # Run detection
        engine = LogoDetectionEngine()
        result = engine.analyze_image(
            image_path=str(test_image),
            sender_email="user@suspicious.com"
        )
        
        # Verify result structure
        assert isinstance(result, DetectionResult)
        assert hasattr(result, 'logo_detected')
        assert hasattr(result, 'verdict')
        assert hasattr(result, 'risk_level')
        assert isinstance(result.recommendations, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
