/**
 * PhishGuard - Main JavaScript
 * 
 * This file contains common JavaScript functionality used across the application
 */

document.addEventListener('DOMContentLoaded', function() {
    // Theme toggling functionality
    initThemeToggle();
    
    // URL form validation
    initUrlFormValidation();
    
    // Initialize tooltips
    initTooltips();
});

/**
 * Initialize theme toggle functionality
 */
function initThemeToggle() {
    const themeToggleBtn = document.getElementById('theme-toggle');
    const darkIcon = document.getElementById('dark-icon');
    const lightIcon = document.getElementById('light-icon');
    const htmlElement = document.documentElement;
    
    // Check for saved theme preference or use device preference
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    // Set initial theme
    if (savedTheme === 'light') {
        setLightTheme();
    } else if (savedTheme === 'dark' || prefersDark) {
        setDarkTheme();
    } else {
        setDarkTheme(); // Default to dark theme
    }
    
    // Toggle theme on button click
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function() {
            if (htmlElement.getAttribute('data-bs-theme') === 'dark') {
                setLightTheme();
            } else {
                setDarkTheme();
            }
        });
    }
    
    function setDarkTheme() {
        htmlElement.setAttribute('data-bs-theme', 'dark');
        if (darkIcon && lightIcon) {
            darkIcon.classList.remove('d-none');
            lightIcon.classList.add('d-none');
        }
        localStorage.setItem('theme', 'dark');
    }
    
    function setLightTheme() {
        htmlElement.setAttribute('data-bs-theme', 'light');
        if (darkIcon && lightIcon) {
            darkIcon.classList.add('d-none');
            lightIcon.classList.remove('d-none');
        }
        localStorage.setItem('theme', 'light');
    }
}

/**
 * Initialize URL form validation
 */
function initUrlFormValidation() {
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url');
    
    if (urlForm && urlInput) {
        urlForm.addEventListener('submit', function(e) {
            // Basic URL validation
            const url = urlInput.value.trim();
            
            // Check if empty
            if (!url) {
                e.preventDefault();
                showInputError(urlInput, 'Please enter a URL');
                return;
            }
            
            // Simple URL format validation
            if (!isValidUrlFormat(url)) {
                e.preventDefault();
                showInputError(urlInput, 'Please enter a valid URL');
                return;
            }
            
            // Show loading state
            document.getElementById('scan-btn').disabled = true;
            document.getElementById('scan-text').classList.add('d-none');
            document.getElementById('scan-spinner').classList.remove('d-none');
        });
        
        // Clear error on input
        urlInput.addEventListener('input', function() {
            clearInputError(urlInput);
        });
    }
}

/**
 * Check if a string is in a valid URL format
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if valid format, false otherwise
 */
function isValidUrlFormat(url) {
    // Very basic URL validation - just check if it has a domain-like structure
    // For proper URL validation, use a more comprehensive regex
    if (url.startsWith('http://') || url.startsWith('https://')) {
        return true;
    }
    
    // Check for domain-like format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
    return domainRegex.test(url);
}

/**
 * Show error message for input field
 * @param {HTMLElement} inputElement - The input element
 * @param {string} message - Error message to display
 */
function showInputError(inputElement, message) {
    inputElement.classList.add('is-invalid');
    
    // Check if error message element already exists
    let errorElement = inputElement.parentElement.querySelector('.invalid-feedback');
    
    if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'invalid-feedback';
        inputElement.parentElement.appendChild(errorElement);
    }
    
    errorElement.textContent = message;
}

/**
 * Clear error message from input field
 * @param {HTMLElement} inputElement - The input element
 */
function clearInputError(inputElement) {
    inputElement.classList.remove('is-invalid');
}

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Format number as percentage
 * @param {number} value - Number between 0 and 1
 * @returns {string} - Formatted percentage string
 */
function formatPercent(value) {
    return (value * 100).toFixed(1) + '%';
}

/**
 * Shorten URL for display if too long
 * @param {string} url - URL to shorten
 * @param {number} maxLength - Maximum length before shortening
 * @returns {string} - Original or shortened URL
 */
function shortenUrl(url, maxLength = 50) {
    if (!url || url.length <= maxLength) {
        return url;
    }
    
    // Try to preserve domain and trim middle
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const path = urlObj.pathname + urlObj.search + urlObj.hash;
        
        if (domain.length + 3 >= maxLength) {
            // Domain itself is too long, just truncate
            return domain.substring(0, maxLength - 3) + '...';
        }
        
        const pathMaxLength = maxLength - domain.length - 3;
        if (path.length <= pathMaxLength) {
            return url;
        }
        
        // Truncate path
        const halfPath = Math.floor(pathMaxLength / 2);
        return urlObj.protocol + '//' + domain + 
               path.substring(0, halfPath) + 
               '...' + 
               path.substring(path.length - halfPath);
    } catch (e) {
        // If URL parsing fails, just do simple truncation
        return url.substring(0, maxLength - 3) + '...';
    }
}
