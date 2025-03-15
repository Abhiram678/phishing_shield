"""Patterns and keywords commonly found in phishing URLs."""

def get_phishing_patterns():
    """
    Return list of common patterns found in phishing URLs.

    Returns:
        list: Common suspicious words and patterns.
    """
    return [
        'secure',
        'account',
        'banking',
        'login',
        'signin',
        'verify',
        'verification',
        'authenticate',
        'wallet',
        'confirm',
        'update',
        'paypal',
        'password',
        'credential',
        'security',
        'apple',
        'microsoft',
        'netflix',
        'amazon',
        'facebook',
        'google',
        'verify-now',
        'auth',
        'access',
        'ebay',
        'recover',
        'unlock',
        'billing',
        'payment',
        'alert',
        'suspended',
        'unusual',
        'activity',
        'support',
        '365',
        'microsoft365',
        'office365',
        'helpdesk'
    ]

def get_suspicious_tlds():
    """
    Return TLDs commonly associated with phishing.

    Returns:
        list: High-risk TLDs.
    """
    return [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top',
        'club', 'online', 'site', 'work', 'live'
    ]