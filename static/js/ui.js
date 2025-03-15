// Display analysis results in the UI
function displayResults(results) {
    try {
        if (!results) {
            showError('No results received from server');
            return;
        }

        console.log('Displaying results:', Object.keys(results));

        // Display overall score
        const overallScoreEl = document.getElementById('overall-score');
        if (!overallScoreEl) {
            console.error('Overall score element not found');
            return;
        }

        const scorePercentage = Math.round(results.overall_score * 100);

        let scoreClass = 'text-success';
        if (results.overall_score >= 0.7) scoreClass = 'text-danger';
        else if (results.overall_score >= 0.4) scoreClass = 'text-warning';

        overallScoreEl.innerHTML = `
            <h2 class="${scoreClass}">${results.risk_level}</h2>
            <p class="lead">URL: <a href="${results.url}" target="_blank">${results.url}</a></p>
            <div class="progress" style="height: 30px;">
                <div class="progress-bar ${getProgressBarClass(results.overall_score)}" 
                    role="progressbar" 
                    style="width: ${scorePercentage}%;" 
                    aria-valuenow="${scorePercentage}" 
                    aria-valuemin="0" 
                    aria-valuemax="100">
                    ${scorePercentage}% Risk Score
                </div>
            </div>
        `;

        // Display detailed results
        const detailedResultsEl = document.getElementById('detailed-results');
        if (detailedResultsEl) {
            detailedResultsEl.innerHTML = generateDetailedResultsHTML(results);
        }

        // Create the risk factors chart
        createRiskChart(results.category_scores);

        // Display technical details if available
        if (results.technical_details) {
            displayTechnicalDetails(results);
        }

        // Display recommendations if available
        if (results.recommendations && results.recommendations.length > 0) {
            displayRecommendations(results.recommendations);
        }
    } catch (error) {
        console.error('Error in displayResults:', error);
        showError('Error displaying results: ' + error.message);
    }
}

function getProgressBarClass(score) {
    if (score >= 0.7) return 'bg-danger';
    if (score >= 0.4) return 'bg-warning';
    return 'bg-success';
}

function generateDetailedResultsHTML(results) {
    try {
        const details = results.details || {};

        let html = '<div class="accordion mt-4" id="resultsAccordion">';

        let i = 0;
        for (const [category, explanation] of Object.entries(details)) {
            if (typeof explanation !== 'string') continue;

            // Make sure category exists in category_scores
            const score = results.category_scores && results.category_scores[category]
                ? results.category_scores[category]
                : 0;
            const scoreClass = getTextColorClass(score);

            html += `
                <div class="accordion-item">
                    <h2 class="accordion-header" id="heading${i}">
                        <button class="accordion-button ${i > 0 ? 'collapsed' : ''}" type="button" 
                                data-bs-toggle="collapse" data-bs-target="#collapse${i}" 
                                aria-expanded="${i === 0}" aria-controls="collapse${i}">
                            ${formatCategoryName(category)} 
                            <span class="ms-auto ${scoreClass}">${Math.round(score * 100)}% risk</span>
                        </button>
                    </h2>
                    <div id="collapse${i}" class="accordion-collapse collapse ${i === 0 ? 'show' : ''}" 
                        aria-labelledby="heading${i}" data-bs-parent="#resultsAccordion">
                        <div class="accordion-body">
                            ${explanation}
                        </div>
                    </div>
                    </div>
            `;
            i++;
        }

        html += '</div>';

        // Add educational section after detailed results
        html += `
            <div class="card mt-4">
                <div class="card-header bg-info text-white">
                    <h5 class="mb-0">How to Stay Safe</h5>
                </div>
                <div class="card-body">
                    <p>Even if a URL appears safe, always remember these security tips:</p>
                    <ul>
                        <li>Verify the sender before clicking links in emails</li>
                        <li>Check for HTTPS and a valid certificate before entering credentials</li>
                        <li>Look for spelling or grammar errors on websites</li>
                        <li>Use different passwords for different websites</li>
                        <li>Enable two-factor authentication when available</li>
                    </ul>
                </div>
            </div>
        `;

        return html;
    } catch (error) {
        console.error('Error generating details HTML:', error);
        return '<div class="alert alert-danger">Error generating detailed results</div>';
    }
}

function displayTechnicalDetails(results) {
    try {
        // Create technical details section if it doesn't exist
        let technicalDetailsCard = document.getElementById('technical-details-card');
        if (!technicalDetailsCard) {
            const detailedResultsEl = document.getElementById('detailed-results');
            if (!detailedResultsEl) {
                console.error('Detailed results element not found');
                return;
            }

            // Create the card element
            technicalDetailsCard = document.createElement('div');
            technicalDetailsCard.id = 'technical-details-card';
            technicalDetailsCard.className = 'card mt-4';

            technicalDetailsCard.innerHTML = `
                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Technical Details</h5>
                    <button class="btn btn-sm btn-light" id="toggle-technical">Hide</button>
                </div>
                <div class="card-body" id="technical-details-content"></div>
            `;

            detailedResultsEl.parentNode.insertBefore(technicalDetailsCard, detailedResultsEl.nextSibling);
        }

        const technicalDetailsContent = document.getElementById('technical-details-content');
        if (!technicalDetailsContent) {
            console.error('Technical details content element not found');
            return;
        }

        const techDetails = results.technical_details;

        if (!techDetails) {
            technicalDetailsContent.innerHTML = '<div class="alert alert-warning">Technical details not available</div>';
            return;
        }

        let techDetailsHTML = '<div class="technical-details">';

        // URL Components
        techDetailsHTML += '<h6>URL Components</h6>';
        techDetailsHTML += '<table class="table table-sm table-bordered">';
        techDetailsHTML += '<tr><th>Component</th><th>Value</th></tr>';
        if (techDetails.url_components) {
            for (const [component, value] of Object.entries(techDetails.url_components)) {
                const displayValue = value === null || value === undefined ? '<em>empty</em>' : value;
                techDetailsHTML += `<tr><td>${component}</td><td>${displayValue}</td></tr>`;
            }
        }
        techDetailsHTML += '</table>';

        // Domain Info
        if (techDetails.domain_parts) {
            techDetailsHTML += '<h6 class="mt-3">Domain Information</h6>';
            techDetailsHTML += '<table class="table table-sm table-bordered">';
            techDetailsHTML += `<tr><td>TLD</td><td>${techDetails.domain_parts.tld || '<em>Unknown</em>'}</td></tr>`;
            techDetailsHTML += `<tr><td>Domain Name</td><td>${techDetails.domain_parts.domain_name || '<em>Unknown</em>'}</td></tr>`;
            techDetailsHTML += `<tr><td>Subdomains</td><td>${techDetails.domain_parts.subdomains || '<em>none</em>'}</td></tr>`;

            if (techDetails.ip_addresses && Array.isArray(techDetails.ip_addresses)) {
                techDetailsHTML += `<tr><td>IP Addresses</td><td>${techDetails.ip_addresses.join(', ')}</td></tr>`;
            }
            techDetailsHTML += '</table>';
        }

        // SSL Info
        if (techDetails.ssl_details) {
            techDetailsHTML += '<h6 class="mt-3">SSL Information</h6>';
            techDetailsHTML += '<table class="table table-sm table-bordered">';
            techDetailsHTML += `<tr><td>HTTPS</td><td>${techDetails.ssl_details.has_ssl ? 'Yes' : 'No'}</td></tr>`;
            techDetailsHTML += `<tr><td>SSL Grade</td><td>${techDetails.ssl_details.ssl_grade || 'Unknown'}</td></tr>`;
            techDetailsHTML += '</table>';
        }

        // WHOIS Info
        if (techDetails.whois_info) {
            techDetailsHTML += '<h6 class="mt-3">WHOIS Information</h6>';
            if (techDetails.whois_info.error) {
                techDetailsHTML += `<div class="alert alert-warning">${techDetails.whois_info.error}</div>`;
            } else {
                techDetailsHTML += '<table class="table table-sm table-bordered">';
                for (const [key, value] of Object.entries(techDetails.whois_info)) {
                    if (key === 'error') continue;

                    // Format dates and arrays
                    let displayValue = value;
                    if (value === null || value === undefined) {
                        displayValue = '<em>Unknown</em>';
                    } else if (Array.isArray(value)) {
                        displayValue = value.join(', ') || '<em>None</em>';
                    } else if (value instanceof Date || (typeof value === 'string' && !isNaN(Date.parse(value)))) {
                        try {
                            const date = value instanceof Date ? value : new Date(value);
                            displayValue = date.toLocaleString();
                        } catch (e) {
                            displayValue = value;
                        }
                    }
                    techDetailsHTML += `<tr><td>${formatCategoryName(key)}</td><td>${displayValue}</td></tr>`;
                }
                techDetailsHTML += '</table>';
            }
        }

        // Suspicious Elements
        if (results.suspicious_elements && Array.isArray(results.suspicious_elements) && results.suspicious_elements.length > 0) {
            techDetailsHTML += '<h6 class="mt-3">Suspicious Elements</h6>';
            techDetailsHTML += '<ul class="list-group">';
            for (const element of results.suspicious_elements) {
                techDetailsHTML += `<li class="list-group-item list-group-item-danger">${element}</li>`;
            }
            techDetailsHTML += '</ul>';
        }

        techDetailsHTML += '</div>';
        technicalDetailsContent.innerHTML = techDetailsHTML;

        // Set up toggle button
        const toggleBtn = document.getElementById('toggle-technical');
        if (toggleBtn) {
            // Remove any existing event listeners
            const newToggleBtn = toggleBtn.cloneNode(true);
            toggleBtn.parentNode.replaceChild(newToggleBtn, toggleBtn);

            newToggleBtn.addEventListener('click', function() {
                const content = document.getElementById('technical-details-content');
                if (content) {
                    if (content.style.display === 'none') {
                        content.style.display = 'block';
                        this.textContent = 'Hide';
                    } else {
                        content.style.display = 'none';
                        this.textContent = 'Show';
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error displaying technical details:', error);
        if (document.getElementById('technical-details-content')) {
            document.getElementById('technical-details-content').innerHTML =
                `<div class="alert alert-danger">Error displaying technical details: ${error.message}</div>`;
        }
    }
}

function displayRecommendations(recommendations) {
    try {
        // Create recommendations section if it doesn't exist
        let recommendationsCard = document.getElementById('recommendations-card');
        if (!recommendationsCard) {
            const technicalCard = document.getElementById('technical-details-card') ||
                                document.getElementById('detailed-results');
            if (!technicalCard) {
                console.error('Could not find parent element for recommendations');
                return;
            }

            // Create the card element
            recommendationsCard = document.createElement('div');
            recommendationsCard.id = 'recommendations-card';
            recommendationsCard.className = 'card mt-4';

            recommendationsCard.innerHTML = `
                <div class="card-header bg-warning text-dark">
                    <h5 class="mb-0">Security Recommendations</h5>
                </div>
                <div class="card-body" id="recommendations-content"></div>
            `;

            technicalCard.parentNode.insertBefore(recommendationsCard, technicalCard.nextSibling);
        }

        const recommendationsContent = document.getElementById('recommendations-content');
        if (!recommendationsContent) {
            console.error('Recommendations content element not found');
            return;
        }

        if (!Array.isArray(recommendations) || recommendations.length === 0) {
            recommendationsContent.innerHTML = '<div class="alert alert-info">No specific recommendations available</div>';
            return;
        }

        let recoHTML = '<ul class="list-group">';
        for (const recommendation of recommendations) {
            recoHTML += `<li class="list-group-item list-group-item-warning">${recommendation}</li>`;
        }
        recoHTML += '</ul>';

        recommendationsContent.innerHTML = recoHTML;
    } catch (error) {
        console.error('Error displaying recommendations:', error);
        if (document.getElementById('recommendations-content')) {
            document.getElementById('recommendations-content').innerHTML =
                `<div class="alert alert-danger">Error displaying recommendations: ${error.message}</div>`;
        }
    }
}

function getTextColorClass(score) {
    if (score >= 0.7) return 'text-danger';
    if (score >= 0.4) return 'text-warning';
    return 'text-success';
}

function formatCategoryName(category) {
    try {
        if (typeof category !== 'string') return String(category);

        return category
            .replace(/([A-Z])/g, ' $1') // Add space before capital letters
            .replace(/_/g, ' ') // Replace underscores with spaces
            .replace(/^./, str => str.toUpperCase()); // Capitalize first letter
    } catch (error) {
        console.error('Error formatting category name:', error);
        return String(category); // Return original as string if formatting fails
    }
}

function createRiskChart(categoryScores) {
    try {
        if (!categoryScores || typeof categoryScores !== 'object' || Object.keys(categoryScores).length === 0) {
            console.error('Invalid category scores:', categoryScores);
            return;
        }

        const chartContainer = document.getElementById('risk-chart');
        if (!chartContainer) {
            console.error('Chart container not found');
            return;
        }

        const ctx = chartContainer.getContext('2d');
        if (!ctx) {
            console.error('Could not get chart context');
            return;
        }

        // If there's an existing chart, destroy it
        if (window.riskChart) {
            window.riskChart.destroy();
        }

        const labels = Object.keys(categoryScores).map(formatCategoryName);
        const data = Object.values(categoryScores).map(score => {
            // Ensure score is a number between 0 and 1
            const numScore = Number(score);
            return isNaN(numScore) ? 0 : Math.max(0, Math.min(1, numScore)) * 100;
        });

        // Check if Chart object exists
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }

        window.riskChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Risk Score (%)',
                    data: data,
                    backgroundColor: data.map(score => {
                        if (score >= 70) return 'rgba(220, 53, 69, 0.7)'; // Danger
                        if (score >= 40) return 'rgba(255, 193, 7, 0.7)'; // Warning
                        return 'rgba(40, 167, 69, 0.7)'; // Success
                    }),
                    borderColor: data.map(score => {
                        if (score >= 70) return 'rgb(220, 53, 69)';
                        if (score >= 40) return 'rgb(255, 193, 7)';
                        return 'rgb(40, 167, 69)';
                    }),
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Risk Score (%)'
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Risk: ${context.raw}%`;
                            }
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error creating risk chart:', error);
    }
}