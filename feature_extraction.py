import re
import logging
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract

def extract_features_from_url(url):
    """
    Extract features from a URL for phishing detection
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary with extracted features
    """
    features = {}
    
    try:
        # Clean URL by removing square brackets and other potentially problematic characters
        cleaned_url = url
        for char in ['[', ']', '{', '}', '|', '\\', '^', '<', '>']:
            cleaned_url = cleaned_url.replace(char, '')
        
        # Parse the URL
        parsed_url = urlparse(cleaned_url)
        extracted = tldextract.extract(cleaned_url)
        
        # Basic URL components
        domain = extracted.domain
        suffix = extracted.suffix
        subdomain = extracted.subdomain
        
        # Feature: Domain length
        features['domain_length'] = len(domain)
        
        # Feature: URL length
        features['url_length'] = len(url)
        
        # Feature: Number of dots in the domain
        features['num_dots'] = url.count('.')
        
        # Feature: Number of hyphens in the domain
        features['num_hyphens'] = domain.count('-')
        
        # Feature: Presence of @ symbol
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # Feature: Presence of double slashes (not at the protocol position)
        features['has_double_slash'] = 1 if url.count('//') > 1 else 0
        
        # Feature: Number of subdomains
        features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
        
        # Feature: Path length
        features['path_length'] = len(parsed_url.path)
        
        # Feature: Number of query parameters
        features['num_query_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        
        # Feature: Presence of IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        features['has_ip_address'] = 1 if re.match(ip_pattern, domain) else 0
        
        # Feature: Presence of suspicious words
        suspicious_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 
                           'confirm', 'password', 'paypal', 'wp-admin', 'security', 'alert', 'update',
                           'verify', 'verification', 'authenticate', 'wallet', 'authorize']
        features['has_suspicious_words'] = 0
        for word in suspicious_words:
            if word in url.lower():
                features['has_suspicious_words'] = 1
                break
                
        # Special check for phishing domains containing brand names but not being the official domain
        brand_domains = {
            'paypal': 'paypal.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'amazon': 'amazon.com',
            'netflix': 'netflix.com',
            'facebook': 'facebook.com',
            'google': 'google.com',
            'bank': None  # Any domain with 'bank' is suspicious if not a known bank
        }
        
        # Check if URL contains a brand name but isn't the official domain
        for brand, official_domain in brand_domains.items():
            if brand in cleaned_url.lower():
                # If it's a brand with an official domain, check if this URL is not that domain
                if official_domain and official_domain not in cleaned_url.lower():
                    features['has_suspicious_words'] = 1
                    break
                # For generic terms like 'bank' without a specific domain
                if official_domain is None:
                    features['has_suspicious_words'] = 1
                    break
        
        # Feature: TLD is common or not
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.co', '.us', '.uk', '.ca', '.au']
        features['is_common_tld'] = 1 if f'.{suffix}' in common_tlds else 0
        
        # Feature: TLD is suspicious (often used in phishing)
        suspicious_tlds = ['.xyz', '.top', '.info', '.site', '.online', '.fit', '.tk', '.ga', '.ml', '.cf', '.gq']
        features['is_suspicious_tld'] = 1 if f'.{suffix}' in suspicious_tlds else 0
        
        # Feature: Domain contains numbers
        features['domain_has_numbers'] = 1 if any(char.isdigit() for char in domain) else 0
        
        # Feature: URL contains 'https'
        features['has_https'] = 1 if 'https://' in url else 0
        
        # Feature: The ratio of digits to URL length
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url)
        
        # Feature: Prefix/suffix separator
        features['has_prefix_suffix'] = 1 if '-' in domain else 0
        
        # Extract more features from the dataset format
        features['having_at_symbol'] = features['has_at_symbol']
        features['having_ip'] = features['has_ip_address']
        features['prefix_suffix_separation'] = features['has_prefix_suffix']
        features['protocol'] = 1 if parsed_url.scheme == 'https' else 0
        features['redirection_symbol'] = features['has_double_slash']
        features['sub_domains'] = 1 if features['num_subdomains'] > 2 else 0
        features['url_length_bin'] = 1 if features['url_length'] > 75 else 0
        features['tiny_url'] = 1 if 'tinyurl' in url or 'bit.ly' in url or 'goo.gl' in url or 't.co' in url else 0
        
        return features
    
    except Exception as e:
        logging.error(f"Error extracting features from URL: {str(e)}")
        # Return default values in case of error
        default_features = {
            'domain_length': 0, 'url_length': 0, 'num_dots': 0, 'num_hyphens': 0,
            'has_at_symbol': 0, 'has_double_slash': 0, 'num_subdomains': 0,
            'path_length': 0, 'num_query_params': 0, 'has_ip_address': 0,
            'has_suspicious_words': 0, 'is_common_tld': 0, 'is_suspicious_tld': 0, 
            'domain_has_numbers': 0, 'has_https': 0, 'digit_ratio': 0, 'has_prefix_suffix': 0,
            'having_at_symbol': 0, 'having_ip': 0, 'prefix_suffix_separation': 0,
            'protocol': 0, 'redirection_symbol': 0, 'sub_domains': 0,
            'url_length_bin': 0, 'tiny_url': 0
        }
        return default_features

def extract_features_from_dataset(df):
    """
    Extract features from a dataset for model training
    
    Args:
        df (pandas.DataFrame): DataFrame containing URL data
        
    Returns:
        pandas.DataFrame: DataFrame with extracted features
    """
    # Initialize feature matrix
    features = df.copy()
    
    # Drop unnecessary columns if present
    if 'label' in features.columns:
        y = features['label']
        features = features.drop('label', axis=1)
    else:
        y = None
    
    # Ensure all feature columns are present
    if 'Domain' in features.columns:
        # Extract more features for each URL if needed
        urls = features['Domain'].tolist()
        extracted_features = []
        
        for url in urls:
            # Add http:// if not present for urlparse to work correctly
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Extract additional features
            url_features = extract_features_from_url(url)
            extracted_features.append(url_features)
        
        # Convert to DataFrame
        additional_features = pd.DataFrame(extracted_features)
        
        # Combine original features with additional features
        features = pd.concat([features, additional_features], axis=1)
    
    # Return features and target if available
    if y is not None:
        return features, y
    else:
        return features
