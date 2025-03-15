"""Domain reputation and age checking functionality."""

import whois
from datetime import datetime, timedelta
import socket
import re
import logging

logger = logging.getLogger(__name__)

def check_domain_reputation(domain):
    """
    Check domain reputation based on registration info.

    Args:
        domain (str): The domain to check.

    Returns:
        float: Risk score between 0 and 1.
    """
    try:
        # Check domain age
        domain_age_score = check_domain_age(domain)
        return domain_age_score
    except Exception as e:
        logger.error("Error checking domain reputation: %s", e)
        return 0.7  # Higher risk score if we can't check the domain

def check_domain_age(domain):
    """
    Check domain age and return a risk score.
    Newer domains are higher risk.

    Args:
        domain (str): The domain to check.

    Returns:
        float: Risk score between 0 and 1.
    """
    try:
        # Get domain information
        domain_info = whois.whois(domain)

        # Extract creation date
        creation_date = domain_info.creation_date

        # Handle multiple dates or none
        if not creation_date:
            logger.warning("No creation date found for domain: %s", domain)
            return 0.8  # Higher risk if no creation date

        # If it's a list, take the first date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate domain age
        domain_age = datetime.now() - creation_date

        # Score based on age
        if domain_age < timedelta(days=30):
            return 0.9  # Very new domain (high risk)
        elif domain_age < timedelta(days=90):
            return 0.7  # Less than 3 months old
        elif domain_age < timedelta(days=365):
            return 0.4  # Less than a year old
        elif domain_age < timedelta(days=365*2):
            return 0.2  # Less than 2 years old

        return 0.1  # Established domain (low risk)

    except Exception as e:
        logger.error("Error in domain age check: %s", e)
        # If there's an error with the whois lookup, assume medium-high risk
        return 0.6

def is_ip_address(domain):
    """
    Check if the domain is actually an IP address.

    Args:
        domain (str): The domain to check.

    Returns:
        bool: True if it's an IP address, False otherwise.
    """
    # Simple regex for IPv4 addresses
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_pattern.match(domain))