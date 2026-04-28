"""
Command-line interface for PhishVision.
Provides a demo entry point for testing the detection engine.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PhishVision - Logo-based Phishing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze an image with sender email
  phish-detect -i screenshot.png -e user@suspicious.com

  # Custom threshold
  phish-detect -i attachment.jpg -t 85

  # List available brands
  phish-detect --list-brands

  # Output as JSON
  phish-detect -i image.png -e test@fake-microsoft.com -o
        """
    )
    
    parser.add_argument(
        '-i', '--image',
        type=str,
        help='Path to image file to analyze'
    )
    parser.add_argument(
        '-e', '--email',
        type=str,
        help='Sender email address for domain validation'
    )
    parser.add_argument(
        '-t', '--threshold',
        type=float,
        default=80.0,
        help='Similarity threshold (0-100, default: 80)'
    )
    parser.add_argument(
        '-o', '--output-json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '--list-brands',
        action='store_true',
        help='List all available reference brands'
    )
    parser.add_argument(
        '--logo-dir',
        type=str,
        help='Custom directory for reference logos'
    )
    
    args = parser.parse_args()
    
    # Handle list brands command
    if args.list_brands:
        from phish_vision import LogoDetectionEngine
        
        engine = LogoDetectionEngine(
            logo_directory=Path(args.logo_dir) if args.logo_dir else None
        )
        
        brands = engine.list_available_brands()
        
        if args.output_json:
            print(json.dumps({"brands": brands}, indent=2))
        else:
            print("\n=== Available Reference Brands ===\n")
            for brand in brands:
                status = "✓" if brand['logo_exists'] else "✗"
                print(f"{status} {brand['name']} ({brand['key']})")
                print(f"   Official domains: {', '.join(brand['domains'])}")
                print()
        return 0
    
    # Require image for analysis
    if not args.image:
        parser.print_help()
        print("\nError: Either --image or --list-brands is required")
        return 1
    
    # Import and run detection
    from phish_vision import LogoDetectionEngine
    
    try:
        engine = LogoDetectionEngine(
            logo_directory=Path(args.logo_dir) if args.logo_dir else None,
            similarity_threshold=args.threshold
        )
        
        result = engine.analyze_image(
            image_path=args.image,
            sender_email=args.email,
            threshold=args.threshold
        )
        
        if args.output_json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print("\n=== PhishVision Analysis Result ===\n")
            print(f"Logo Detected: {'Yes' if result.logo_detected else 'No'}")
            if result.brand:
                print(f"Brand: {result.brand}")
                print(f"Similarity Score: {result.similarity_score:.1f}%")
                print(f"Match Count: {result.match_count}")
                print(f"Confidence: {result.confidence}")
            print(f"\nVerdict: {result.verdict}")
            print(f"Risk Level: {result.risk_level.value.upper()}")
            
            if result.domain_validation:
                print(f"\nDomain Validation: {result.domain_validation}")
            
            if result.sender_domain:
                print(f"Sender Domain: {result.sender_domain}")
                if result.official_domains:
                    print(f"Official Domains: {', '.join(result.official_domains)}")
            
            print("\nRecommendations:")
            for rec in result.recommendations:
                print(f"  • {rec}")
            print()
        
        # Return exit code based on risk level
        if result.risk_level.value == "critical":
            return 2
        elif result.risk_level.value == "high":
            return 1
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
