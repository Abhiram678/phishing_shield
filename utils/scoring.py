"""Risk scoring system for phishing detection."""

import logging

logger = logging.getLogger(__name__)

# Default weights for scoring
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

def calculate_overall_score(scores):
    """
    Calculate weighted overall risk score.

    Args:
        scores (dict): Dictionary of individual scores for each category.

    Returns:
        float: Weighted risk score between 0 and 1.
    """
    try:
        if not scores or not isinstance(scores, dict):
            logger.warning("Invalid scores provided: %s", scores)
            return 0.5  # Default medium risk

        weighted_score = 0
        total_weight = 0

        for category, score in scores.items():
            if category in SCORING_WEIGHTS:
                weight = SCORING_WEIGHTS.get(category, 0)
                weighted_score += score * weight
                total_weight += weight

        # Normalize if some categories are missing
        if total_weight > 0:
            weighted_score = weighted_score / total_weight
        else:
            logger.warning("No valid categories found in scores")
            return 0.5  # Default medium risk

        # Ensure score is between 0 and 1
        return max(0, min(weighted_score, 1))
    except Exception as e:
        logger.exception("Error calculating overall score: %s", e)
        return 0.5  # Default medium risk on error

def get_risk_level(score):
    """
    Determine risk level based on score.

    Args:
        score (float): The calculated risk score.

    Returns:
        str: Risk level description.
    """
    try:
        if score >= HIGH_RISK_THRESHOLD:
            return "High Risk"
        elif score >= MEDIUM_RISK_THRESHOLD:
            return "Medium Risk"
        elif score >= LOW_RISK_THRESHOLD:
            return "Low Risk"
        else:
            return "Very Low Risk"
    except Exception as e:
        logger.exception("Error determining risk level: %s", e)
        return "Unknown Risk"