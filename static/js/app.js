document.addEventListener('DOMContentLoaded', function() {
    // Form submission handler
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const resultsSection = document.getElementById('results-section');

    if (!urlForm || !urlInput || !resultsSection) {
        console.error('Required elements not found in the DOM');
        return;
    }

    // Check if there's a URL in the query string (from history page)
    const urlParams = new URLSearchParams(window.location.search);
    const urlFromQuery = urlParams.get('url');

    if (urlFromQuery) {
        urlInput.value = urlFromQuery;
        analyzeUrl(urlFromQuery);
    }

    urlForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }

        analyzeUrl(url);
    });

    // Initialize storage for history
    initStorage();
});

async function analyzeUrl(url) {
    // Show loading state
    showLoading(true);

    try {
        console.log('Submitting URL for analysis:', url);

        // Call the Flask API
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
        });

        console.log('Server response status:', response.status);

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Server returned non-JSON response');
        }

        const results = await response.json();
        console.log('Analysis results received');

        // Hide loading state
        showLoading(false);

        if (results.error) {
            showError(results.error);
            return;
        }

        // Validate required fields
        if (!validateResults(results)) {
            showError('Invalid or incomplete data received from server');
            console.error('Invalid results structure:', results);
            return;
        }

        // Display results
        displayResults(results);

        // Save to history
        saveToHistory(url, results);

        // Show results section
        document.getElementById('results-section').style.display = 'block';

        // Scroll to results
        document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });

    } catch (error) {
        showLoading(false);
        showError('Error analyzing URL: ' + error.message);
        console.error('Error:', error);
    }
}

function validateResults(results) {
    // Check that results contains all required fields
    return results &&
           typeof results === 'object' &&
           'overall_score' in results &&
           'category_scores' in results &&
           'risk_level' in results;
}

function showLoading(isLoading) {
    const button = document.querySelector('#url-form button');
    if (!button) {
        console.error('Submit button not found');
        return;
    }

    if (isLoading) {
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
        button.disabled = true;
    } else {
        button.innerHTML = 'Analyze URL';
        button.disabled = false;
    }
}

function showError(message) {
    console.error(message);

    // Create alert if it doesn't exist
    let alertElement = document.getElementById('error-alert');
    if (!alertElement) {
        alertElement = document.createElement('div');
        alertElement.id = 'error-alert';
        alertElement.className = 'alert alert-danger alert-dismissible fade show mt-3';
        alertElement.innerHTML = `
            <span id="error-message"></span>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        const formCard = document.querySelector('#url-form').closest('.card');
        if (formCard) {
            formCard.insertAdjacentElement('afterend', alertElement);
        } else {
            // Fallback if form card not found
            const container = document.querySelector('.container');
            if (container) {
                container.prepend(alertElement);
            }
        }
    }

    // Update error message and show alert
    const errorMessage = document.getElementById('error-message');
    if (errorMessage) {
        errorMessage.textContent = message;
    }

    // Hide results if they were displayed
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) {
        resultsSection.style.display = 'none';
    }
}

// Local storage functions
function initStorage() {
    if (!localStorage.getItem('phishingShieldHistory')) {
        localStorage.setItem('phishingShieldHistory', JSON.stringify([]));
    }
}

function saveToHistory(url, results) {
    if (!results || typeof results.overall_score === 'undefined' || !results.risk_level) {
        console.error('Cannot save incomplete results to history');
        return;
    }

    try {
        const history = JSON.parse(localStorage.getItem('phishingShieldHistory') || '[]');

        // Add new entry
        history.unshift({
            url,
            timestamp: new Date().toISOString(),
            overall_score: results.overall_score,
            risk_level: results.risk_level
        });

        // Keep only the last 20 entries
        const updatedHistory = history.slice(0, 20);

        localStorage.setItem('phishingShieldHistory', JSON.stringify(updatedHistory));
    } catch (error) {
        console.error('Error saving to history:', error);
    }
}