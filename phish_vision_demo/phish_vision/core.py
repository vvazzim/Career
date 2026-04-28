"""
Core detection engine for PhishVision.
Implements SIFT-based logo detection and phishing analysis.
"""

import cv2
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from phish_vision.models import DetectionResult, RiskLevel
from phish_vision.database import BrandDatabase


class LogoDetectionEngine:
    """
    Computer Vision engine for detecting brand logos and analyzing
    potential phishing attempts.
    
    Uses SIFT (Scale-Invariant Feature Transform) for robust feature
    matching against a reference database of official brand logos.
    """
    
    def __init__(self, 
                 logo_directory: Optional[Path] = None,
                 similarity_threshold: float = 80.0,
                 min_match_count: int = 10):
        """
        Initialize the detection engine.
        
        Args:
            logo_directory: Path to directory containing reference logos.
            similarity_threshold: Minimum similarity score (0-100) to consider a match.
            min_match_count: Minimum number of feature matches required.
        """
        self.database = BrandDatabase(logo_directory)
        self.similarity_threshold = similarity_threshold
        self.min_match_count = min_match_count
        
        # Initialize SIFT detector
        self.sift = cv2.SIFT_create()
        
        # FLANN parameters for feature matching
        self.flann_params = {
            'algorithm': 1,  # FLANN_INDEX_KDTREE
            'trees': 5
        }
        self.match_params = {
            'checks': 50
        }
        
        # Lowe's ratio test threshold
        self.ratio_threshold = 0.75
        
        # Pre-compute features for all reference logos
        self.reference_features: Dict[str, dict] = {}
        self._load_reference_logos()
    
    def _load_reference_logos(self):
        """Pre-compute SIFT features for all reference logos."""
        for brand_key in self.database.list_brands():
            logo_path = self.database.get_logo_path(brand_key)
            if logo_path and logo_path.exists():
                try:
                    image = cv2.imread(str(logo_path))
                    if image is not None:
                        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                        keypoints, descriptors = self.sift.detectAndCompute(gray, None)
                        
                        if descriptors is not None:
                            self.reference_features[brand_key] = {
                                'keypoints': keypoints,
                                'descriptors': descriptors,
                                'image_shape': image.shape
                            }
                except Exception as e:
                    print(f"Warning: Could not load logo for {brand_key}: {e}")
    
    def _extract_features(self, image: np.ndarray) -> Tuple[List, Optional[np.ndarray]]:
        """
        Extract SIFT features from an image.
        
        Args:
            image: Input image as numpy array (BGR format).
            
        Returns:
            Tuple of (keypoints, descriptors).
        """
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image
        
        return self.sift.detectAndCompute(gray, None)
    
    def _calculate_similarity(self, 
                              query_descriptors: Optional[np.ndarray],
                              ref_descriptors: np.ndarray) -> Tuple[int, float]:
        """
        Calculate similarity between query and reference descriptors.
        
        Args:
            query_descriptors: Descriptors from the input image.
            ref_descriptors: Descriptors from the reference logo.
            
        Returns:
            Tuple of (match_count, similarity_score).
        """
        if query_descriptors is None or len(query_descriptors) == 0:
            return 0, 0.0
        
        # Create FLANN matcher
        flann = cv2.FlannBasedMatcher(self.flann_params, self.match_params)
        
        # Perform KNN matching
        matches = flann.knnMatch(query_descriptors, ref_descriptors, k=2)
        
        # Apply Lowe's ratio test
        good_matches = []
        for match_pair in matches:
            if len(match_pair) == 2:
                m, n = match_pair
                if m.distance < self.ratio_threshold * n.distance:
                    good_matches.append(m)
        
        match_count = len(good_matches)
        
        # Calculate similarity score (normalized)
        # Score based on match count relative to reference descriptor count
        if len(ref_descriptors) > 0:
            similarity = (match_count / len(ref_descriptors)) * 100
            # Cap at 100%
            similarity = min(similarity, 100.0)
        else:
            similarity = 0.0
        
        return match_count, similarity
    
    def _extract_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address."""
        if not email or '@' not in email:
            return None
        return email.split('@')[-1].lower().strip('.')
    
    def _determine_confidence(self, similarity: float, match_count: int) -> str:
        """Determine confidence level based on score and match count."""
        if similarity >= 90 and match_count >= 50:
            return "very_high"
        elif similarity >= 80 and match_count >= 30:
            return "high"
        elif similarity >= 60 and match_count >= 20:
            return "medium"
        elif similarity >= 40 and match_count >= 10:
            return "low"
        else:
            return "very_low"
    
    def _generate_recommendations(self, result: DetectionResult) -> List[str]:
        """Generate actionable recommendations based on detection result."""
        recommendations = []
        
        if result.risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Block sender immediately",
                "Quarantine all emails from this domain",
                "Alert security team for investigation",
                "Check for similar domains in recent emails",
                "Consider user awareness training"
            ])
        elif result.risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Flag email for manual review",
                "Verify sender identity through alternate channel",
                "Do not click any links or download attachments"
            ])
        elif result.risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Exercise caution with this email",
                "Verify sender domain authenticity",
                "Check email headers for spoofing indicators"
            ])
        else:
            recommendations.append("No immediate action required")
        
        return recommendations
    
    def analyze_image(self, 
                      image_path: str,
                      sender_email: Optional[str] = None,
                      threshold: Optional[float] = None) -> DetectionResult:
        """
        Analyze an image for brand logo impersonation.
        
        Args:
            image_path: Path to the image file to analyze.
            sender_email: Optional sender email for domain validation.
            threshold: Optional custom similarity threshold (overrides default).
            
        Returns:
            DetectionResult with analysis findings.
        """
        threshold = threshold if threshold is not None else self.similarity_threshold
        
        # Load image
        image = cv2.imread(image_path)
        if image is None:
            return DetectionResult(
                logo_detected=False,
                verdict="Failed to load image",
                risk_level=RiskLevel.LOW,
                recommendations=["Verify image file path and format"]
            )
        
        # Extract features from input image
        kp_query, des_query = self._extract_features(image)
        
        if des_query is None or len(des_query) == 0:
            return DetectionResult(
                logo_detected=False,
                verdict="No distinctive features detected in image",
                risk_level=RiskLevel.LOW,
                recommendations=["Image may be too simple, blurry, or low resolution"]
            )
        
        # Compare against all reference logos
        best_match: Optional[str] = None
        best_score = 0.0
        best_match_count = 0
        
        for brand_key, ref_data in self.reference_features.items():
            match_count, similarity = self._calculate_similarity(
                des_query, 
                ref_data['descriptors']
            )
            
            if similarity > best_score:
                best_score = similarity
                best_match_count = match_count
                best_match = brand_key
        
        # Determine if logo was detected
        logo_detected = (best_score >= threshold and 
                        best_match_count >= self.min_match_count)
        
        # Extract sender domain if provided
        sender_domain = self._extract_domain(sender_email) if sender_email else None
        
        # Build result
        if logo_detected and best_match:
            brand_name = self.database.get_display_name(best_match)
            official_domains = self.database.get_official_domains(best_match)
            
            # Validate domain
            is_official = False
            domain_validation = ""
            
            if sender_domain:
                is_official = self.database.is_official_domain(best_match, sender_domain)
                if is_official:
                    domain_validation = f"Sender domain '{sender_domain}' is verified for {brand_name}"
                else:
                    domain_validation = f"Sender domain '{sender_domain}' does NOT match official {brand_name} domains"
            else:
                domain_validation = "No sender email provided for domain validation"
            
            # Determine verdict and risk level
            if is_official:
                verdict = "Benign - Verified sender domain"
                risk_level = RiskLevel.LOW
            elif not sender_domain:
                verdict = f"Potential impersonation of {brand_name} - Manual review required"
                risk_level = RiskLevel.MEDIUM
            else:
                verdict = f"High Risk Phishing - {brand_name} impersonation detected"
                risk_level = RiskLevel.CRITICAL
            
            confidence = self._determine_confidence(best_score, best_match_count)
            
            result = DetectionResult(
                logo_detected=True,
                brand=brand_name,
                similarity_score=best_score,
                match_count=best_match_count,
                confidence=confidence,
                verdict=verdict,
                risk_level=risk_level,
                domain_validation=domain_validation,
                sender_domain=sender_domain,
                official_domains=official_domains
            )
        else:
            # No logo detected above threshold
            result = DetectionResult(
                logo_detected=False,
                similarity_score=best_score,
                match_count=best_match_count,
                confidence=self._determine_confidence(best_score, best_match_count),
                verdict="No known brand logo detected",
                risk_level=RiskLevel.LOW,
                sender_domain=sender_domain
            )
        
        # Add recommendations
        result.recommendations = self._generate_recommendations(result)
        
        return result
    
    def list_available_brands(self) -> List[Dict[str, str]]:
        """List all brands available in the reference database."""
        brands = []
        for brand_key in self.database.list_brands():
            logo_path = self.database.get_logo_path(brand_key)
            brands.append({
                "key": brand_key,
                "name": self.database.get_display_name(brand_key),
                "logo_exists": logo_path.exists() if logo_path else False,
                "domains": self.database.get_official_domains(brand_key)
            })
        return brands
