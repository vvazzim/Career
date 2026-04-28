#!/usr/bin/env python3
"""
Phishing Logo Detection Engine
==============================
A computer vision-based module for detecting brand logo impersonation in images.
Designed to be embedded within security automation platforms (e.g., Cortex XSOAR).

This module provides:
- SIFT-based feature matching for robust logo detection
- Similarity scoring against a reference database
- Domain validation logic for phishing risk assessment
- Structured output compatible with SOAR platforms
"""

import os
import sys
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

# Third-party imports
try:
    import cv2
    import numpy as np
except ImportError as e:
    print(f"Critical dependency missing: {e}")
    print("Please install requirements: pip install opencv-python numpy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class BrandReference:
    """Represents a reference brand with its official domains and logo features."""
    name: str
    official_domains: List[str]
    logo_path: str
    keypoints: Optional[Any] = None
    descriptors: Optional[Any] = None


@dataclass
class DetectionResult:
    """Structured result from the phishing detection analysis."""
    logo_detected: bool
    brand: Optional[str]
    similarity_score: float
    match_count: int
    confidence: str
    verdict: str
    risk_level: str
    domain_validation: Optional[str]
    recommendations: List[str]
    input_file: str
    sender_email: Optional[str]


class LogoDetectionEngine:
    """
    Core engine for detecting brand logos using computer vision.
    
    Uses SIFT (Scale-Invariant Feature Transform) for feature extraction
    and FLANN (Fast Library for Approximate Nearest Neighbors) for matching.
    """
    
    # Minimum number of good matches required for confident detection
    MIN_MATCH_COUNT = 4
    
    # Lowe's ratio test threshold for filtering ambiguous matches
    RATIO_THRESHOLD = 0.75
    
    def __init__(self, reference_db_path: str):
        """
        Initialize the detection engine.
        
        Args:
            reference_db_path: Path to directory containing reference logo images.
                              Expected structure: <brand_name>.png (e.g., microsoft.png)
        """
        self.reference_db_path = reference_db_path
        self.reference_brands: Dict[str, BrandReference] = {}
        
        # Initialize SIFT detector
        self.sift = cv2.SIFT_create()
        
        # Initialize FLANN matcher
        flann_params = dict(algorithm=1, trees=5)  # KDTree index params
        search_params = dict(checks=50)
        self.flann = cv2.FlannBasedMatcher(flann_params, search_params)
        
        # Official domain mappings (extend as needed)
        self.official_domains_map = {
            'microsoft': ['microsoft.com', 'office365.com', 'outlook.com', 'live.com'],
            'paypal': ['paypal.com', 'paypal.me', 'py.pl'],
            'bankofamerica': ['bankofamerica.com', 'bofa.com'],
            'amazon': ['amazon.com', 'amazonaws.com', 'amzn.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com'],
            'netflix': ['netflix.com', 'nflxso.net'],
            'facebook': ['facebook.com', 'fb.com', 'meta.com'],
            'linkedin': ['linkedin.com', 'lnkd.in'],
            'dropbox': ['dropbox.com', 'getdropbox.com'],
        }
        
        self._load_reference_database()
    
    def _load_reference_database(self) -> None:
        """Load and pre-compute features for all reference logos."""
        if not os.path.isdir(self.reference_db_path):
            logger.warning(f"Reference database path does not exist: {self.reference_db_path}")
            return
        
        for filename in os.listdir(self.reference_db_path):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                brand_name = os.path.splitext(filename)[0].lower()
                logo_path = os.path.join(self.reference_db_path, filename)
                
                try:
                    # Load and preprocess logo
                    logo_img = cv2.imread(logo_path, cv2.IMREAD_GRAYSCALE)
                    if logo_img is None:
                        logger.warning(f"Could not load image: {logo_path}")
                        continue
                    
                    # Compute SIFT features
                    kp, des = self.sift.detectAndCompute(logo_img, None)
                    
                    if des is None or len(des) == 0:
                        logger.warning(f"No features detected in logo: {filename}")
                        continue
                    
                    # Store reference
                    self.reference_brands[brand_name] = BrandReference(
                        name=brand_name.capitalize(),
                        official_domains=self.official_domains_map.get(brand_name, []),
                        logo_path=logo_path,
                        keypoints=kp,
                        descriptors=des
                    )
                    logger.info(f"Loaded reference logo: {brand_name} ({len(kp)} keypoints)")
                    
                except Exception as e:
                    logger.error(f"Error loading reference logo {filename}: {e}")
    
    def _extract_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address."""
        if not email or '@' not in email:
            return None
        try:
            return email.split('@')[1].lower().strip()
        except Exception:
            return None
    
    def _is_official_domain(self, domain: str, brand_name: str) -> bool:
        """Check if domain belongs to official brand domains."""
        if not domain or not brand_name:
            return False
        
        official_domains = self.official_domains_map.get(brand_name.lower(), [])
        
        # Check exact match or subdomain
        for official in official_domains:
            if domain == official or domain.endswith('.' + official):
                return True
        return False
    
    def _calculate_similarity(
        self, 
        query_descriptors: np.ndarray, 
        reference_descriptors: np.ndarray
    ) -> Tuple[int, float]:
        """
        Calculate similarity between query and reference descriptors.
        
        Returns:
            Tuple of (match_count, similarity_percentage)
        """
        if reference_descriptors is None or len(reference_descriptors) == 0:
            return 0, 0.0
        
        # Ensure descriptors are float32 for FLANN
        query_descriptors = np.float32(query_descriptors)
        reference_descriptors = np.float32(reference_descriptors)
        
        # Find matches using FLANN
        matches = self.flann.knnMatch(query_descriptors, reference_descriptors, k=2)
        
        # Apply Lowe's ratio test
        good_matches = []
        for m, n in matches:
            if m.distance < self.RATIO_THRESHOLD * n.distance:
                good_matches.append(m)
        
        match_count = len(good_matches)
        
        # Calculate similarity percentage
        # Normalize by the minimum of query and reference keypoints
        if len(query_descriptors) > 0 and len(reference_descriptors) > 0:
            max_possible_matches = min(len(query_descriptors), len(reference_descriptors))
            similarity = (match_count / max_possible_matches) * 100
        else:
            similarity = 0.0
        
        # Cap at 100%
        similarity = min(similarity, 100.0)
        
        return match_count, similarity
    
    def detect_logo(
        self, 
        image_path: str, 
        sender_email: Optional[str] = None,
        similarity_threshold: float = 80.0
    ) -> DetectionResult:
        """
        Analyze an image for brand logo impersonation.
        
        Args:
            image_path: Path to the image file to analyze
            sender_email: Email address of the sender (for domain validation)
            similarity_threshold: Minimum similarity score to consider a match (0-100)
        
        Returns:
            DetectionResult with analysis findings
        """
        # Validate input file
        if not os.path.isfile(image_path):
            return DetectionResult(
                logo_detected=False,
                brand=None,
                similarity_score=0.0,
                match_count=0,
                confidence="none",
                verdict="Error: File not found",
                risk_level="low",
                domain_validation=None,
                recommendations=["Verify file path and retry"],
                input_file=image_path,
                sender_email=sender_email
            )
        
        # Load and preprocess image
        try:
            image = cv2.imread(image_path, cv2.IMREAD_COLOR)
            if image is None:
                raise ValueError("cv2.imread returned None")
            
            gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Detect SIFT features
            kp, des = self.sift.detectAndCompute(gray_image, None)
            
            if des is None or len(des) == 0:
                return DetectionResult(
                    logo_detected=False,
                    brand=None,
                    similarity_score=0.0,
                    match_count=0,
                    confidence="none",
                    verdict="No features detected in image",
                    risk_level="low",
                    domain_validation=None,
                    recommendations=["Ensure image contains clear visual content"],
                    input_file=image_path,
                    sender_email=sender_email
                )
            
        except Exception as e:
            logger.error(f"Error processing image {image_path}: {e}")
            return DetectionResult(
                logo_detected=False,
                brand=None,
                similarity_score=0.0,
                match_count=0,
                confidence="none",
                verdict=f"Error: {str(e)}",
                risk_level="low",
                domain_validation=None,
                recommendations=["Check image format and integrity"],
                input_file=image_path,
                sender_email=sender_email
            )
        
        # Compare against all reference brands
        best_match_brand = None
        best_match_score = 0.0
        best_match_count = 0
        
        for brand_name, brand_ref in self.reference_brands.items():
            match_count, similarity = self._calculate_similarity(des, brand_ref.descriptors)
            
            if similarity > best_match_score:
                best_match_score = similarity
                best_match_count = match_count
                best_match_brand = brand_name
        
        # Determine verdict based on results
        extracted_domain = self._extract_domain(sender_email) if sender_email else None
        
        if best_match_brand and best_match_score >= similarity_threshold:
            # Logo detected above threshold
            is_official = self._is_official_domain(extracted_domain, best_match_brand) if extracted_domain else False
            
            if is_official:
                verdict = "Benign - Official Domain"
                risk_level = "low"
                confidence = "high" if best_match_score > 90 else "medium"
                domain_validation = f"Sender domain '{extracted_domain}' matches official {best_match_brand} domains"
                recommendations = [
                    "No immediate action required",
                    "Continue standard email processing"
                ]
            else:
                verdict = "High Risk Phishing"
                risk_level = "critical"
                confidence = "high" if best_match_score > 90 else "high"
                if extracted_domain:
                    domain_validation = f"Sender domain '{extracted_domain}' does NOT match official {best_match_brand} domains"
                else:
                    domain_validation = "No sender email provided for domain validation"
                recommendations = [
                    "Block sender immediately",
                    "Quarantine all emails from this sender",
                    "Investigate other emails from same domain",
                    "Alert security team for manual review",
                    "Check for similar domains (typosquatting)",
                    "Review email headers for spoofing indicators"
                ]
            
            return DetectionResult(
                logo_detected=True,
                brand=self.reference_brands[best_match_brand].name,
                similarity_score=round(best_match_score, 2),
                match_count=best_match_count,
                confidence=confidence,
                verdict=verdict,
                risk_level=risk_level,
                domain_validation=domain_validation,
                recommendations=recommendations,
                input_file=image_path,
                sender_email=sender_email
            )
        
        elif best_match_brand and best_match_score >= 50:
            # Moderate match but below threshold
            return DetectionResult(
                logo_detected=True,
                brand=self.reference_brands[best_match_brand].name,
                similarity_score=round(best_match_score, 2),
                match_count=best_match_count,
                confidence="low",
                verdict="Potential Impersonation (Below Threshold)",
                risk_level="medium",
                domain_validation=f"Similarity score {best_match_score:.1f}% is below threshold {similarity_threshold}%",
                recommendations=[
                    "Manual review recommended",
                    "Consider lowering threshold if false negatives occur",
                    "Cross-reference with other phishing indicators"
                ],
                input_file=image_path,
                sender_email=sender_email
            )
        
        else:
            # No significant match
            return DetectionResult(
                logo_detected=False,
                brand=None,
                similarity_score=round(best_match_score, 2),
                match_count=best_match_count,
                confidence="none",
                verdict="No Known Brand Logo Detected",
                risk_level="low",
                domain_validation=None,
                recommendations=[
                    "No brand impersonation detected",
                    "Continue with other security checks"
                ],
                input_file=image_path,
                sender_email=sender_email
            )
    
    def list_reference_brands(self) -> List[Dict[str, Any]]:
        """Return list of available reference brands."""
        return [
            {
                'name': brand.name,
                'official_domains': brand.official_domains,
                'keypoints_count': len(brand.keypoints) if brand.keypoints else 0
            }
            for brand in self.reference_brands.values()
        ]


def main():
    """
    Main entry point for standalone execution or integration.
    
    When integrated into a SOAR platform, this function serves as the
    command handler that processes arguments and returns structured results.
    """
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description='Phishing Logo Detection Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python PhishingLogoDetection.py --image screenshot.png --email user@suspicious.com
  python PhishingLogoDetection.py --image attachment.jpg --threshold 85
  python PhishingLogoDetection.py --list-brands
        """
    )
    
    parser.add_argument(
        '--image', '-i',
        type=str,
        help='Path to image file to analyze (email screenshot or attachment)'
    )
    parser.add_argument(
        '--email', '-e',
        type=str,
        help='Sender email address for domain validation'
    )
    parser.add_argument(
        '--threshold', '-t',
        type=float,
        default=80.0,
        help='Similarity threshold percentage (default: 80.0)'
    )
    parser.add_argument(
        '--reference-db', '-r',
        type=str,
        default='./reference_logos',
        help='Path to reference logo database directory'
    )
    parser.add_argument(
        '--list-brands', '-l',
        action='store_true',
        help='List available reference brands and exit'
    )
    parser.add_argument(
        '--output-json', '-o',
        action='store_true',
        help='Output results as JSON'
    )
    
    args = parser.parse_args()
    
    # Initialize engine
    engine = LogoDetectionEngine(reference_db_path=args.reference_db)
    
    # Handle list brands command
    if args.list_brands:
        brands = engine.list_reference_brands()
        if args.output_json:
            print(json.dumps(brands, indent=2))
        else:
            print(f"\nAvailable Reference Brands ({len(brands)}):")
            print("-" * 60)
            for brand in brands:
                print(f"  • {brand['name']}")
                print(f"    Keypoints: {brand['keypoints_count']}")
                print(f"    Official Domains: {', '.join(brand['official_domains']) if brand['official_domains'] else 'None configured'}")
                print()
        return
    
    # Handle detection command
    if not args.image:
        parser.print_help()
        print("\nError: --image argument is required for detection")
        sys.exit(1)
    
    # Run detection
    result = engine.detect_logo(
        image_path=args.image,
        sender_email=args.email,
        similarity_threshold=args.threshold
    )
    
    # Output results
    if args.output_json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print("\n" + "=" * 60)
        print("PHISHING LOGO DETECTION RESULTS")
        print("=" * 60)
        print(f"Input File:      {result.input_file}")
        print(f"Sender Email:    {result.sender_email or 'Not provided'}")
        print(f"Logo Detected:   {'Yes' if result.logo_detected else 'No'}")
        if result.brand:
            print(f"Brand:           {result.brand}")
        print(f"Similarity:      {result.similarity_score:.2f}%")
        print(f"Match Count:     {result.match_count}")
        print(f"Confidence:      {result.confidence.upper()}")
        print(f"Verdict:         {result.verdict}")
        print(f"Risk Level:      {result.risk_level.upper()}")
        if result.domain_validation:
            print(f"Domain Check:    {result.domain_validation}")
        print("\nRecommendations:")
        for i, rec in enumerate(result.recommendations, 1):
            print(f"  {i}. {rec}")
        print("=" * 60)


if __name__ == '__main__':
    main()
