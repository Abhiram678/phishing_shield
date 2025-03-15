// Frontend scoring utilities
// This file contains scoring-related functions that might be used on the client side

// Format score for display
function formatScore(score) {
    return Math.round(score * 100) + '%';
}

// Get risk level text based on score
function getRiskLevelText(score) {
    if (score >= 0.8) return 'High Risk';
    if (score >= 0.6) return 'Medium-High Risk';
    if (score >= 0.4) return 'Medium Risk';
    if (score >= 0.2) return 'Low-Medium Risk';
    return 'Low Risk';
}

// Get appropriate CSS class for risk level
function getRiskLevelClass(score) {
    if (score >= 0.7) return 'high-risk';
    if (score >= 0.4) return 'medium-risk';
    if (score >= 0.2) return 'low-risk';
    return 'very-low-risk';
}

// Basic URL validation
function isValidUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch (e) {
        // Try adding https:// and checking again
        try {
            const urlWithProtocol = 'https://' + url;
            const urlObj = new URL(urlWithProtocol);
            return true;
        } catch (e) {
            return false;
        }
    }
}

// Count suspicious elements in URL
function countSuspiciousElements(url) {
    let count = 0;

    // Check for special characters
    const specialChars = url.match(/[^a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]/g) || [];
    count += specialChars.length;

    // Check for excessive subdomains
    const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
    const subdomains = urlObj.hostname.split('.').length - 1;
    if (subdomains > 2) count += subdomains - 2;

    // Check for URL length
    if (url.length > 100) count += 3;
    else if (url.length > 75) count += 2;
    else if (url.length > 50) count += 1;

    return count;
}