"""Configuration settings for the Phishing Shield application."""

# Flask application settings
DEBUG = True
SECRET_KEY = 'your-secret-key-here'  # Change this in production

# Scoring weights
SCORING_WEIGHTS = {
    'url_structure': 0.25,
    'domain_age': 0.20,
    'tld_risk': 0.15,
    'ssl_analysis': 0.15,
    'suspicious_patterns': 0.25
}

# Risk thresholds
LOW_RISK_THRESHOLD = 0.3
MEDIUM_RISK_THRESHOLD = 0.6
HIGH_RISK_THRESHOLD = 0.8

# External API keys (if needed)
WHOIS_API_KEY = ''  # Add your API key if using a paid WHOIS service

# Features toggle
ENABLE_DOMAIN_AGE_CHECK = True
ENABLE_CONTENT_ANALYSIS = False  # Set to True if implementing website content analysis