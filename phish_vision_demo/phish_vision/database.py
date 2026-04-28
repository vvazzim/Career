"""
Brand database management for PhishVision.
Contains official brand domains and logo metadata.
"""

from typing import Dict, List, Optional
from pathlib import Path


class BrandDatabase:
    """
    Manages reference brand information including official domains
    and logo file paths.
    """
    
    # Pre-configured brands with their official domains
    DEFAULT_BRANDS: Dict[str, Dict] = {
        "microsoft": {
            "domains": ["microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com"],
            "logo_file": "microsoft.png",
            "display_name": "Microsoft"
        },
        "paypal": {
            "domains": ["paypal.com", "paypal-me.com"],
            "logo_file": "paypal.png",
            "display_name": "PayPal"
        },
        "bankofamerica": {
            "domains": ["bankofamerica.com", "bofa.com"],
            "logo_file": "bankofamerica.png",
            "display_name": "Bank of America"
        },
        "amazon": {
            "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
            "logo_file": "amazon.png",
            "display_name": "Amazon"
        },
        "apple": {
            "domains": ["apple.com", "icloud.com", "me.com"],
            "logo_file": "apple.png",
            "display_name": "Apple"
        },
        "google": {
            "domains": ["google.com", "gmail.com", "youtube.com", "android.com"],
            "logo_file": "google.png",
            "display_name": "Google"
        },
        "netflix": {
            "domains": ["netflix.com"],
            "logo_file": "netflix.png",
            "display_name": "Netflix"
        },
        "facebook": {
            "domains": ["facebook.com", "fb.com", "messenger.com"],
            "logo_file": "facebook.png",
            "display_name": "Facebook"
        },
        "linkedin": {
            "domains": ["linkedin.com", "lnkd.in"],
            "logo_file": "linkedin.png",
            "display_name": "LinkedIn"
        },
        "dropbox": {
            "domains": ["dropbox.com", "getdropbox.com"],
            "logo_file": "dropbox.png",
            "display_name": "Dropbox"
        }
    }
    
    def __init__(self, logo_directory: Optional[Path] = None):
        """
        Initialize the brand database.
        
        Args:
            logo_directory: Path to directory containing logo images.
                           Defaults to ./data/logos relative to package.
        """
        if logo_directory is None:
            # Default to package data directory
            self.logo_directory = Path(__file__).parent.parent / "data" / "logos"
        else:
            self.logo_directory = Path(logo_directory)
        
        self.brands = self.DEFAULT_BRANDS.copy()
    
    def get_brand_info(self, brand_key: str) -> Optional[Dict]:
        """Get information for a specific brand."""
        return self.brands.get(brand_key.lower())
    
    def get_official_domains(self, brand_key: str) -> List[str]:
        """Get list of official domains for a brand."""
        brand_info = self.get_brand_info(brand_key)
        if brand_info:
            return brand_info.get("domains", [])
        return []
    
    def get_logo_path(self, brand_key: str) -> Optional[Path]:
        """Get full path to a brand's logo file."""
        brand_info = self.get_brand_info(brand_key)
        if brand_info:
            logo_file = brand_info.get("logo_file")
            if logo_file:
                return self.logo_directory / logo_file
        return None
    
    def list_brands(self) -> List[str]:
        """List all available brand keys."""
        return list(self.brands.keys())
    
    def get_display_name(self, brand_key: str) -> str:
        """Get human-readable display name for a brand."""
        brand_info = self.get_brand_info(brand_key)
        if brand_info:
            return brand_info.get("display_name", brand_key)
        return brand_key
    
    def is_official_domain(self, brand_key: str, domain: str) -> bool:
        """
        Check if a domain is official for a given brand.
        
        Args:
            brand_key: The brand identifier (e.g., 'microsoft')
            domain: The domain to check (e.g., 'microsoft.com')
            
        Returns:
            True if domain is official for the brand, False otherwise.
        """
        official_domains = self.get_official_domains(brand_key)
        domain_lower = domain.lower().strip('.')
        
        # Check exact match or subdomain match
        for official in official_domains:
            if domain_lower == official or domain_lower.endswith('.' + official):
                return True
        return False
    
    def add_custom_brand(self, brand_key: str, domains: List[str], 
                         logo_file: str, display_name: Optional[str] = None):
        """
        Add a custom brand to the database.
        
        Args:
            brand_key: Unique identifier for the brand
            domains: List of official domains
            logo_file: Filename of the logo image
            display_name: Human-readable name (defaults to brand_key)
        """
        self.brands[brand_key.lower()] = {
            "domains": [d.lower() for d in domains],
            "logo_file": logo_file,
            "display_name": display_name or brand_key
        }
