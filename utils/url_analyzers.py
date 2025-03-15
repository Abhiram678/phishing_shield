"""URL analysis functions for phishing detection."""

import re
import urllib.parse
import socket
from datetime import datetime
import whois
import logging

logger = logging.getLogger(__name__)

# Import other utility functions
# If these are missing, we'll define simplified versions here for testing
try:
    from utils.scoring import calculate_overall_score, get_risk_level
    from utils.domain_check import check_domain_reputation, is_ip_address
    from utils.phising_patterns import get_phishing_patterns
except ImportError:
    logger.warning("Could not import all utility modules, using simplified versions")

    def calculate_overall_score(scores):
        """Calculate weighted overall risk score."""
        return sum(scores.values()) / len(scores) if scores else 0.5

    def get_risk_level(score):
        """Get risk level based on score."""
        if score >= 0.7: return "High Risk"
        if score >= 0.4: return "Medium Risk"
        return "Low Risk"

    def check_domain_reputation(domain):
        """Simple domain reputation check."""
        return 0.5  # Default medium risk

    def is_ip_address(domain):
        """Check if domain is an IP address."""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(domain))

    def get_phishing_patterns():
        """Return list of phishing patterns."""
        return ["login", "secure", "account", "verify", "bank"]

def analyze_url(url):
    """
    Analyze a URL for phishing indicators with comprehensive details.

    Args:
        url (str): The URL to analyze.

    Returns:
        dict: Detailed analysis results including scores, risk level, and technical details.
    """
    logger.info(f"Starting analysis of URL: {url}")

    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        # Parse URL components
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc

            logger.debug(f"Parsed URL: scheme={parsed_url.scheme}, domain={domain}")

            if not domain:
                raise ValueError("No domain found in URL")

        except Exception as e:
            logger.error(f"Error parsing URL: {e}")
            return {
                'error': f"Failed to parse URL: {str(e)}",
                'url': url
            }

        # Extract all URL components for detailed analysis
        url_components = {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment
        }

        # Domain details
        try:
            domain_parts = domain.split('.')
            tld = domain_parts[-1] if len(domain_parts) > 1 else ''
            domain_name = domain_parts[-2] if len(domain_parts) > 1 else domain
            subdomains = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else ''

            logger.debug(f"Domain parts: tld={tld}, domain_name={domain_name}, subdomains={subdomains}")
        except Exception as e:
            logger.error(f"Error processing domain parts: {e}")
            tld = ''
            domain_name = domain
            subdomains = ''

        # Get IP address information
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            logger.debug(f"IP addresses: {ip_addresses}")
        except Exception as e:
            logger.error(f"Error resolving IP: {e}")
            ip_addresses = ['Could not resolve']

        # Check for SSL
        ssl_details = {
            'has_ssl': parsed_url.scheme == 'https',
            'ssl_grade': 'A' if parsed_url.scheme == 'https' else 'F'  # Simplified, would need real SSL check
        }

        # Check domain registration
        whois_info = {}
        try:
            domain_info = whois.whois(domain)
            whois_info = {
                'registrar': domain_info.registrar or 'Unknown',
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
                'last_updated': domain_info.updated_date,
                'country': domain_info.country or 'Unknown',
                'name_servers': domain_info.name_servers
            }

            # Calculate domain age
            creation_date = domain_info.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                domain_age = datetime.now() - creation_date
                whois_info['age_days'] = domain_age.days

            logger.debug(f"WHOIS info retrieved successfully")
        except Exception as e:
            logger.error(f"Error retrieving WHOIS info: {e}")
            whois_info = {'error': 'Could not retrieve WHOIS information'}

        # Security analysis
        suspicious_elements = []

        # Check for IP in domain
        if is_ip_address(domain):
            suspicious_elements.append("IP address used as domain")

        # Check for excessive subdomains
        if len(domain_parts) > 3:
            suspicious_elements.append(f"Excessive subdomains: {len(domain_parts)-2} levels deep")

        # Check for long URL
        if len(url) > 100:
            suspicious_elements.append(f"Unusually long URL ({len(url)} characters)")

        # Check for unusual characters
        special_chars = re.findall(r'[^a-zA-Z0-9-.]', domain)
        if special_chars:
            suspicious_elements.append(f"Special characters in domain: {' '.join(special_chars)}")

        # Check for suspicious keywords
        phishing_keywords = get_phishing_patterns()
        matched_keywords = [keyword for keyword in phishing_keywords if keyword in url.lower()]
        if matched_keywords:
            suspicious_elements.append(f"Suspicious keywords detected: {', '.join(matched_keywords)}")

        logger.debug(f"Found {len(suspicious_elements)} suspicious elements")

        # Get all scoring components
        try:
            url_structure_score = score_url_structure(url, parsed_url)
            domain_score = check_domain_reputation(domain)
            tld_score = score_tld(domain)
            ssl_score = 0.1 if parsed_url.scheme == 'https' else 0.9
            patterns_score = score_suspicious_patterns(url)

            # Combine scores
            scores = {
                'url_structure': url_structure_score,
                'domain_age': domain_score,
                'tld_risk': tld_score,
                'ssl_analysis': ssl_score,
                'suspicious_patterns': patterns_score
            }

            logger.debug(f"Category scores: {scores}")

            overall_score = calculate_overall_score(scores)
            logger.debug(f"Overall score: {overall_score}")

        except Exception as e:
            logger.error(f"Error calculating scores: {e}")
            # Provide default scores in case of error
            scores = {
                'url_structure': 0.5,
                'domain_age': 0.5,
                'tld_risk': 0.5,
                'ssl_analysis': 0.5,
                'suspicious_patterns': 0.5
            }
            overall_score = 0.5

        # Generate recommendations
        recommendations = generate_recommendations(scores, suspicious_elements)

        # Build the response object
        result = {
            'url': url,
            'overall_score': overall_score,
            'category_scores': scores,
            'risk_level': get_risk_level(overall_score),
            'details': generate_details(scores, url, parsed_url, domain),
            'technical_details': {
                'url_components': url_components,
                'domain_parts': {
                    'tld': tld,
                    'domain_name': domain_name,
                    'subdomains': subdomains
                },
                'ip_addresses': ip_addresses,
                'ssl_details': ssl_details,
                'whois_info': whois_info
            },
            'suspicious_elements': suspicious_elements,
            'recommendations': recommendations
        }

        logger.info(f"Analysis complete for {url}: {get_risk_level(overall_score)}")
        return result

    except Exception as e:
        logger.exception(f"Unhandled exception analyzing URL: {e}")
        return {
            'error': f"Failed to analyze URL: {str(e)}",
            'url': url
        }

def score_url_structure(url, parsed_url):
    """
    Score URL structure based on common phishing indicators.

    Args:
        url (str): The full URL.
        parsed_url (ParseResult): Parsed URL components.

    Returns:
        float: Risk score between 0 and 1.
    """
    try:
        score = 0
        domain = parsed_url.netloc

        # Check URL length
        if len(url) > 100:
            score += 0.4
        elif len(url) > 75:
            score += 0.3
        elif len(url) > 50:
            score += 0.2

        # Check for special characters in domain
        special_chars = re.findall(r'[^a-zA-Z0-9-.]', domain)
        special_char_ratio = len(special_chars) / len(domain) if domain else 0
        if special_char_ratio > 0.1:
            score += 0.3

        # Check for IP address
        if is_ip_address(domain):
            score += 0.9  # Very high risk for IP-based URLs

        # Check for excessive subdomains
        subdomain_parts = domain.split('.')
        if len(subdomain_parts) > 4:
            score += 0.4
        elif len(subdomain_parts) > 3:
            score += 0.2

        # Check for URL shorteners
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
        if any(shortener in domain for shortener in url_shorteners):
            score += 0.5

        # Check for excessive use of query parameters
        if len(parsed_url.query) > 100:
            score += 0.3

        # Check for numeric subdomain (often used in phishing)
        if re.match(r'^\d+\.', domain):
            score += 0.4

        return min(score, 1.0)  # Cap at 1.0
    except Exception as e:
        logger.error(f"Error in score_url_structure: {e}")
        return 0.5  # Default medium risk if error

def score_tld(domain):
    """
    Score TLD risk.

    Args:
        domain (str): The domain to check.

    Returns:
        float: Risk score between 0 and 1.
    """
    try:
        high_risk_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site', 'work']
        medium_risk_tlds = ['info', 'biz', 'me', 'ws']

        tld = domain.split('.')[-1].lower()

        if tld in high_risk_tlds:
            return 0.8
        elif tld in medium_risk_tlds:
            return 0.5

        return 0.2  # Default for standard TLDs
    except Exception as e:
        logger.error(f"Error in score_tld: {e}")
        return 0.5  # Default medium risk if error

def score_suspicious_patterns(url):
    """
    Score URL based on suspicious patterns and keywords.

    Args:
        url (str): The URL to analyze.

    Returns:
        float: Risk score between 0 and 1.
    """
    try:
        url_lower = url.lower()
        suspicious_patterns = get_phishing_patterns()

        matched_patterns = [pattern for pattern in suspicious_patterns
                           if pattern in url_lower]

        # Score based on number of matches
        if len(matched_patterns) >= 3:
            return 0.9
        elif len(matched_patterns) == 2:
            return 0.7
        elif len(matched_patterns) == 1:
            return 0.5

        return 0.1  # No matches
    except Exception as e:
        logger.error(f"Error in score_suspicious_patterns: {e}")
        return 0.5  # Default medium risk if error

def generate_details(scores, url, parsed_url, domain):
    """
    Generate detailed explanation of results.

    Args:
        scores (dict): Category scores.
        url (str): The URL being analyzed.
        parsed_url (ParseResult): Parsed URL components.
        domain (str): The domain from the URL.

    Returns:
        dict: Detailed explanations for each risk factor.
    """
    try:
        details = {
            'url_structure': url_structure_details(scores['url_structure'], url),
            'domain_age': domain_age_details(scores['domain_age']),
            'tld_risk': tld_risk_details(scores['tld_risk'], domain),
            'ssl_analysis': ssl_analysis_details(scores['ssl_analysis'], parsed_url.scheme),
            'suspicious_patterns': patterns_details(scores['suspicious_patterns'], url)
        }

        return details
    except Exception as e:
        logger.error(f"Error generating details: {e}")
        return {
            'error': f"Could not generate detailed explanations: {str(e)}"
        }

def url_structure_details(score, url):
    """Generate explanation for URL structure score."""
    if score > 0.7:
        return "URL structure has multiple high-risk characteristics including excessive length, special characters, or unusual formatting. These are common in phishing URLs designed to confuse users."
    elif score > 0.3:
        return "URL structure has some suspicious elements that are sometimes associated with phishing sites, but not conclusively malicious."
    return "URL structure appears normal and follows standard conventions."

def domain_age_details(score):
    """Generate explanation for domain age score."""
    if score > 0.7:
        return "Domain appears to be newly registered or has characteristics commonly associated with phishing sites. Phishing sites often use newly registered domains."
    elif score > 0.3:
        return "Domain has some characteristics that might indicate risk, but is not definitively suspicious. It may be relatively new but not extremely recent."
    return "Domain appears to be legitimate based on registration data. It has been registered for a sufficient period, which is typical of established legitimate websites."

def tld_risk_details(score, domain):
    """Generate explanation for TLD risk score."""
    try:
        tld = domain.split('.')[-1].lower()

        if score > 0.7:
            return f"The TLD '{tld}' is frequently associated with malicious websites due to lower registration requirements and costs. Free or very cheap domains are often used in phishing campaigns."
        elif score > 0.3:
            return f"The TLD '{tld}' has moderate risk, as it's sometimes used for malicious purposes, though many legitimate sites also use this TLD."
        return f"The TLD '{tld}' is commonly used for legitimate websites and has a good reputation."
    except:
        return "Unable to analyze the TLD (top-level domain) risk."

def ssl_analysis_details(score, scheme):
    """Generate explanation for SSL analysis score."""
    if scheme == 'https':
        return "Website uses secure HTTPS connection, which is a positive security indicator. However, note that many phishing sites now also use HTTPS certificates."
    return "Website doesn't use HTTPS, which is a security concern for any site requesting personal information. Legitimate sites typically use encrypted connections."

def patterns_details(score, url):
    """Generate explanation for suspicious patterns score."""
    if score > 0.7:
        return "Multiple keywords or patterns associated with phishing were detected in this URL. These patterns are commonly used in fraudulent sites to impersonate legitimate services."
    elif score > 0.3:
        return "Some keywords or patterns associated with phishing were detected, but this alone isn't definitive proof of malicious intent."
    return "No suspicious keywords or patterns commonly associated with phishing were detected."

def generate_recommendations(scores, suspicious_elements):
    """Generate security recommendations based on analysis."""
    try:
        recommendations = []

        if scores['ssl_analysis'] > 0.5:
            recommendations.append("Do not enter sensitive information on this site as it doesn't use HTTPS encryption")

        if scores['domain_age'] > 0.6:
            recommendations.append("Be cautious with this domain as it appears to be newly registered")

        if scores['url_structure'] > 0.5:
            recommendations.append("The URL structure contains suspicious elements - verify the website's legitimacy before proceeding")

        if len(suspicious_elements) > 2:
            recommendations.append("Multiple red flags detected - strongly recommend avoiding this website")

        overall_score = calculate_overall_score(scores)
        if overall_score > 0.7:
            recommendations.append("HIGH RISK: This URL shows strong indicators of being a phishing attempt")

        # Add general recommendations
        if not recommendations:
            recommendations.append("No specific security concerns detected, but always remain vigilant")

        recommendations.append("Never share passwords or personal information unless you're 100% confident in the site's legitimacy")

        return recommendations
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        return ["Unable to generate specific recommendations due to an error"]