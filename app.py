import os
import logging
import json
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Import utilities after logging is configured
from feature_extraction import extract_features_from_url
from model import HybridPhishingDetector
from utils import load_model, save_scan_history

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Load the pre-trained model
model = load_model()

@app.route('/')
def index():
    """Render the home page with URL input form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Process the URL and detect if it's a phishing URL"""
    try:
        url = request.form.get('url', '').strip()
        
        # Basic validation
        if not url:
            flash('Please enter a URL', 'warning')
            return redirect(url_for('index'))
        
        # Add http if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Store URL in session for animation
        session['scan_url'] = url
            
        # Redirect to the animation page
        return redirect(url_for('scan_animation'))
    
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        flash(f'Error processing URL: {str(e)}', 'danger')
        return redirect(url_for('index'))
        
@app.route('/scan-animation')
def scan_animation():
    """Show the animation for URL scanning"""
    if 'scan_url' not in session:
        flash('No URL to scan', 'warning')
        return redirect(url_for('index'))
        
    url = session['scan_url']
    return render_template('scan_animation.html', url=url)
    
@app.route('/process-url', methods=['POST'])
def process_url():
    """Process the URL and return results in JSON format"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
            
        url = data['url'].strip()
        
        # Check whitelist before feature extraction
        legitimate_domains = [
            'paypal.com', 'apple.com', 'microsoft.com', 'amazon.com', 
            'netflix.com', 'facebook.com', 'google.com', 'bankofamerica.com',
            'chase.com', 'wellsfargo.com', 'citi.com', 'gmail.com',
            'yahoo.com', 'live.com', 'outlook.com', 'ebay.com'
        ]
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Direct whitelist check for common legitimate domains
        is_whitelisted = any(domain.endswith(f".{legit}") or domain == legit for legit in legitimate_domains)
        
        if is_whitelisted:
            logging.info(f"URL {url} is on whitelist with domain {domain}")
            result = {
                'is_phishing': False,
                'confidence': 0.05,
                'rf_confidence': 0.0,
                'lstm_confidence': 0.0,
                'threshold': 0.3,
                'whitelisted': True
            }
        else:
            # Extract features from URL
            features = extract_features_from_url(url)
            
            # Add original URL for context
            features['url'] = url
            
            # Make prediction using model
            result = model.predict(features)
        
        logging.info(f"Prediction for {url}: {result}")
        
        # Extract features if not already done (for whitelisted domains)
        if not 'features' in locals() or features is None:
            features = extract_features_from_url(url)
            features['url'] = url
            
        # Store scan in history
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_data = {
            'url': url,
            'is_phishing': bool(result['is_phishing']),
            'confidence': float(result['confidence']),
            'threshold': result.get('threshold', 0.3),  # Include the threshold, default to 0.3 if not present
            'whitelisted': result.get('whitelisted', False),
            'timestamp': timestamp,
            'features': {k: float(v) if isinstance(v, (np.float32, np.float64)) else v 
                         for k, v in features.items()}
        }
        
        # Save scan history
        save_scan_history(scan_data)
        
        # Store the result in session for the results page
        session['scan_result'] = json.dumps(scan_data, default=str)
        
        return jsonify(scan_data)
    
    except Exception as e:
        logging.error(f"Error during processing: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/results')
def results():
    """Display the results of the URL scan"""
    if 'scan_result' not in session:
        flash('No scan results to display', 'warning')
        return redirect(url_for('index'))
    
    scan_result = json.loads(session['scan_result'])
    return render_template('results.html', result=scan_result)

@app.route('/dashboard')
def dashboard():
    """Display dashboard with scan history and statistics"""
    try:
        # Load scan history
        scan_history_file = os.path.join('data', 'scan_history.json')
        
        if os.path.exists(scan_history_file):
            with open(scan_history_file, 'r') as f:
                scan_history = json.load(f)
        else:
            scan_history = []
        
        # Calculate stats
        total_scans = len(scan_history)
        phishing_detected = sum(1 for scan in scan_history if scan['is_phishing'])
        safe_urls = total_scans - phishing_detected
        
        # Get recent scans (last 10)
        recent_scans = scan_history[-10:][::-1]
        
        stats = {
            'total_scans': total_scans,
            'phishing_detected': phishing_detected,
            'safe_urls': safe_urls,
            'recent_scans': recent_scans
        }
        
        return render_template('dashboard.html', stats=stats)
    
    except Exception as e:
        logging.error(f"Error loading dashboard: {str(e)}")
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/education')
def education():
    """Display educational content about phishing"""
    return render_template('education.html')

@app.route('/api')
def api_docs():
    """Display API documentation"""
    return render_template('api.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for URL scanning"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        # Add http if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Check whitelist before feature extraction
        legitimate_domains = [
            'paypal.com', 'apple.com', 'microsoft.com', 'amazon.com', 
            'netflix.com', 'facebook.com', 'google.com', 'bankofamerica.com',
            'chase.com', 'wellsfargo.com', 'citi.com', 'gmail.com',
            'yahoo.com', 'live.com', 'outlook.com', 'ebay.com'
        ]
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Direct whitelist check for common legitimate domains
        is_whitelisted = any(domain.endswith(f".{legit}") or domain == legit for legit in legitimate_domains)
        
        if is_whitelisted:
            logging.info(f"API: URL {url} is on whitelist with domain {domain}")
            result = {
                'is_phishing': False,
                'confidence': 0.05,
                'rf_confidence': 0.0,
                'lstm_confidence': 0.0,
                'threshold': 0.3,
                'whitelisted': True
            }
        else:
            # Extract features from URL
            features = extract_features_from_url(url)
            
            # Add original URL for context
            features['url'] = url
            
            # Make prediction using model
            result = model.predict(features)
        
        logging.info(f"API prediction for {url}: {result}")
        
        # Extract features if not already done (for whitelisted domains)
        if not 'features' in locals() or features is None:
            features = extract_features_from_url(url)
            features['url'] = url
        
        # Prepare response
        response = {
            'url': url,
            'is_phishing': bool(result['is_phishing']),
            'confidence': float(result['confidence']),
            'threshold': result.get('threshold', 0.3),  # Include the threshold, default to 0.3 if not present
            'whitelisted': result.get('whitelisted', False),
            'features': {k: float(v) if isinstance(v, (np.float32, np.float64)) else v 
                         for k, v in features.items()}
        }
        
        # Store scan in history
        scan_data = response.copy()
        scan_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        save_scan_history(scan_data)
        
        return jsonify(response)
    
    except Exception as e:
        logging.error(f"API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Create data directory if it doesn't exist
if not os.path.exists('data'):
    os.makedirs('data')

# Create models directory if it doesn't exist
if not os.path.exists('models'):
    os.makedirs('models')
