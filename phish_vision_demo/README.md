# PhishVision

Computer Vision-based phishing detection library using logo recognition. Detects brand impersonation in email attachments and screenshots by comparing logos against a reference database.

## Features

- **SIFT Feature Matching**: Robust logo detection using Scale-Invariant Feature Transform
- **Brand Database**: Pre-configured with 10 major brands (Microsoft, PayPal, Amazon, etc.)
- **Domain Validation**: Cross-references sender domain against official brand domains
- **Risk Assessment**: Automatic risk level classification (Low, Medium, High, Critical)
- **Actionable Recommendations**: Generates security response recommendations
- **Platform Agnostic**: Works standalone or integrated into security automation platforms

## Installation

```bash
# Clone or copy the package directory
cd phish_vision_demo

# Install dependencies
pip install -r requirements.txt

# Install package in development mode
pip install -e .
```

## Quick Start

### Command Line Usage

```bash
# List available reference brands
phish-detect --list-brands

# Analyze an image
phish-detect -i screenshot.png -e sender@suspicious.com

# Output as JSON
phish-detect -i attachment.jpg -e user@fake-microsoft.com -o

# Custom threshold
phish-detect -i image.png -t 85
```

### Python API Usage

```python
from phish_vision import LogoDetectionEngine, RiskLevel

# Initialize engine
engine = LogoDetectionEngine(
    logo_directory="./data/logos",  # Optional: custom logo directory
    similarity_threshold=80.0,       # Optional: custom threshold
    min_match_count=10               # Optional: minimum matches required
)

# Analyze an image
result = engine.analyze_image(
    image_path="email_screenshot.png",
    sender_email="user@suspicious-domain.com"
)

# Check results
print(f"Logo Detected: {result.logo_detected}")
print(f"Brand: {result.brand}")
print(f"Similarity: {result.similarity_score:.1f}%")
print(f"Verdict: {result.verdict}")
print(f"Risk Level: {result.risk_level.value}")

# Convert to dict for JSON serialization
result_dict = result.to_dict()

# Handle based on risk level
if result.risk_level == RiskLevel.CRITICAL:
    print("🚨 HIGH RISK PHISHING DETECTED!")
    for rec in result.recommendations:
        print(f"  • {rec}")
```

### Integration Example (Security Automation)

```python
# Example: Process email attachment in automation workflow
def process_email_attachment(file_path: str, sender_email: str):
    from phish_vision import LogoDetectionEngine, RiskLevel
    
    engine = LogoDetectionEngine()
    result = engine.analyze_image(file_path, sender_email)
    
    if result.risk_level == RiskLevel.CRITICAL:
        # Trigger high-risk response
        return {
            "action": "quarantine",
            "reason": result.verdict,
            "brand": result.brand,
            "confidence": result.confidence
        }
    elif result.risk_level == RiskLevel.MEDIUM:
        # Flag for review
        return {"action": "review", "reason": result.verdict}
    else:
        return {"action": "allow"}
```

## Project Structure

```
phish_vision/
├── __init__.py      # Package exports
├── core.py          # Main detection engine
├── database.py      # Brand database management
├── models.py        # Data classes and enums
├── cli.py           # Command-line interface
└── data/
    └── logos/       # Reference logo images
```

## Adding Custom Brands

```python
from phish_vision import LogoDetectionEngine

engine = LogoDetectionEngine()

# Add a custom brand
engine.database.add_custom_brand(
    brand_key="mycompany",
    domains=["mycompany.com", "my-company.net"],
    logo_file="mycompany.png",
    display_name="My Company"
)

# Place logo file in data/logos/mycompany.png
```

## Output Format

### DetectionResult Fields

| Field | Type | Description |
|-------|------|-------------|
| `logo_detected` | bool | Whether a known logo was detected |
| `brand` | str | Name of detected brand (if any) |
| `similarity_score` | float | Match confidence (0-100%) |
| `match_count` | int | Number of feature matches |
| `confidence` | str | Confidence level (very_low to very_high) |
| `verdict` | str | Human-readable assessment |
| `risk_level` | RiskLevel | Enum: low, medium, high, critical |
| `domain_validation` | str | Domain verification status |
| `sender_domain` | str | Extracted sender domain |
| `official_domains` | list | Official domains for detected brand |
| `recommendations` | list | Actionable security recommendations |

### Example JSON Output

```json
{
  "logo_detected": true,
  "brand": "Microsoft",
  "similarity_score": 92.5,
  "match_count": 156,
  "confidence": "very_high",
  "verdict": "High Risk Phishing - Microsoft impersonation detected",
  "risk_level": "critical",
  "domain_validation": "Sender domain 'fake-ms.com' does NOT match official Microsoft domains",
  "sender_domain": "fake-ms.com",
  "official_domains": ["microsoft.com", "office.com", "outlook.com"],
  "recommendations": [
    "Block sender immediately",
    "Quarantine all emails from this domain",
    "Alert security team for investigation"
  ]
}
```

## Requirements

- Python 3.8+
- OpenCV 4.8+
- NumPy 1.24+
- Pillow 9.0+

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## License

MIT License
