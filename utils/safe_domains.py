"""Database of known safe domains."""

def get_safe_domains():
    """
    Return a list of known legitimate domains that are frequently targeted by phishers.

    Returns:
        list: Legitimate domains often spoofed in phishing attempts.
    """
    return [
        'google.com',
        'facebook.com',
        'apple.com',
        'microsoft.com',
        'amazon.com',
        'paypal.com',
        'netflix.com',
        'instagram.com',
        'twitter.com',
        'linkedin.com',
        'yahoo.com',
        'gmail.com',
        'outlook.com',
        'live.com',
        'icloud.com',
        'dropbox.com',
        'github.com',
        'chase.com',
        'bankofamerica.com',
        'wellsfargo.com',
        'citi.com',
        'capitalone.com',
        'adobe.com',
        'spotify.com',
        'walmart.com'
    ]

def is_domain_safe(domain):
    """
    Check if a domain is in the safe domains list.

    Args:
        domain (str): The domain to check.

    Returns:
        bool: True if domain is in safe list, False otherwise.
    """
    safe_domains = get_safe_domains()

    # First check exact match
    if domain in safe_domains:
        return True

    # Then check if it's a subdomain of a safe domain
    for safe_domain in safe_domains:
        if domain.endswith('.' + safe_domain):
            return True

    return False