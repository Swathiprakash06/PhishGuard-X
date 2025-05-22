/**
 * PhishGuard - Chart.js Integration
 * 
 * This file contains functions for initializing and updating charts
 * used throughout the application.
 */

/**
 * Creates a pie chart showing detection results
 * @param {string} elementId - The ID of the canvas element
 * @param {Object} data - Data for the chart
 */
function createDetectionPieChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Safe URLs', 'Phishing URLs'],
            datasets: [{
                data: [data.safeCount, data.phishingCount],
                backgroundColor: [
                    'rgba(40, 167, 69, 0.7)',
                    'rgba(220, 53, 69, 0.7)'
                ],
                borderColor: [
                    'rgba(40, 167, 69, 1)',
                    'rgba(220, 53, 69, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'Detection Results'
                }
            }
        }
    });
}

/**
 * Creates a bar chart showing feature importance
 * @param {string} elementId - The ID of the canvas element
 * @param {Object} data - Feature importance data
 */
function createFeatureImportanceChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // Sort features by importance
    const sortedFeatures = Object.entries(data)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10); // Top 10 features
    
    const labels = sortedFeatures.map(f => formatFeatureName(f[0]));
    const values = sortedFeatures.map(f => f[1]);
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Feature Importance',
                data: values,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Top 10 Important Features'
                }
            }
        }
    });
}

/**
 * Creates a line chart showing scan history over time
 * @param {string} elementId - The ID of the canvas element
 * @param {Object} data - Historical scan data
 */
function createHistoryLineChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [
                {
                    label: 'Safe URLs',
                    data: data.safeCount,
                    borderColor: 'rgba(40, 167, 69, 1)',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'Phishing URLs',
                    data: data.phishingCount,
                    borderColor: 'rgba(220, 53, 69, 1)',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'Scan History'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

/**
 * Creates a radar chart showing feature values
 * @param {string} elementId - The ID of the canvas element
 * @param {Object} features - URL features
 */
function createFeatureRadarChart(elementId, features) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // Select key features for the radar chart
    const keyFeatures = [
        'url_length', 'domain_length', 'num_dots', 'num_subdomains',
        'path_length', 'has_suspicious_words', 'has_https',
        'has_ip_address', 'digit_ratio'
    ];
    
    const featureValues = keyFeatures.map(f => features[f] || 0);
    const maxValues = {
        'url_length': 100,
        'domain_length': 30,
        'num_dots': 5,
        'num_subdomains': 5,
        'path_length': 50,
        'has_suspicious_words': 1,
        'has_https': 1,
        'has_ip_address': 1,
        'digit_ratio': 1
    };
    
    // Normalize values between 0 and 1
    const normalizedValues = keyFeatures.map((f, i) => {
        const maxVal = maxValues[f] || 1;
        return featureValues[i] / maxVal;
    });
    
    return new Chart(ctx, {
        type: 'radar',
        data: {
            labels: keyFeatures.map(f => formatFeatureName(f)),
            datasets: [{
                label: 'Feature Values',
                data: normalizedValues,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1,
                pointBackgroundColor: 'rgba(54, 162, 235, 1)'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'URL Feature Profile'
                }
            },
            scales: {
                r: {
                    angleLines: {
                        display: true
                    },
                    suggestedMin: 0,
                    suggestedMax: 1
                }
            }
        }
    });
}

/**
 * Format feature names for display
 * @param {string} name - Raw feature name
 * @returns {string} - Formatted feature name
 */
function formatFeatureName(name) {
    // Replace underscores with spaces
    let formatted = name.replace(/_/g, ' ');
    
    // Capitalize each word
    formatted = formatted.replace(/\b\w/g, l => l.toUpperCase());
    
    // Specific replacements for better readability
    const replacements = {
        'Url': 'URL',
        'Ip': 'IP',
        'Http': 'HTTP',
        'Https': 'HTTPS',
        'Num': 'Number of'
    };
    
    // Apply replacements
    for (const [key, value] of Object.entries(replacements)) {
        formatted = formatted.replace(new RegExp('\\b' + key + '\\b', 'g'), value);
    }
    
    return formatted;
}

/**
 * Create a doughnut chart for model contribution
 * @param {string} elementId - The ID of the canvas element
 * @param {number} rfContribution - Random Forest contribution
 * @param {number} lstmContribution - LSTM contribution
 */
function createModelContributionChart(elementId, rfContribution, lstmContribution) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Random Forest', 'LSTM Network'],
            datasets: [{
                data: [rfContribution, lstmContribution],
                backgroundColor: [
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 159, 64, 0.7)'
                ],
                borderColor: [
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 159, 64, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            var label = context.label || '';
                            var value = context.raw || 0;
                            return label + ': ' + value.toFixed(1) + '%';
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Model Contribution'
                }
            }
        }
    });
}
