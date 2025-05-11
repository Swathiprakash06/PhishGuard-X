import os
import json
import logging
import pandas as pd
import numpy as np
from model import HybridPhishingDetector

def load_model():
    """
    Load the pre-trained model or train a new one if it doesn't exist
    """
    model_path = os.path.join('models', 'hybrid_phishing_detector.pkl')
    
    try:
        if os.path.exists(model_path):
            logging.info("Loading existing model...")
            return HybridPhishingDetector.load(model_path)
        else:
            logging.info("No existing model found. Training a new model...")
            return train_new_model()
    except Exception as e:
        logging.error(f"Error loading model: {str(e)}")
        logging.info("Training a new model due to loading error...")
        return train_new_model()

def train_new_model():
    """
    Train a new model using the provided datasets
    """
    from train import train_model
    
    try:
        # Define paths to datasets
        phishing_data_path = os.path.join('attached_assets', 'phishing-urls.csv')
        legitimate_data_path = os.path.join('attached_assets', 'legitimate-urls.csv')
        
        # Train the model
        model = train_model(phishing_data_path, legitimate_data_path)
        
        # Save the model
        model_path = os.path.join('models', 'hybrid_phishing_detector.pkl')
        model.save(model_path)
        
        return model
    except Exception as e:
        logging.error(f"Error training new model: {str(e)}")
        # Return a fallback model
        return HybridPhishingDetector()

def save_scan_history(scan_data):
    """
    Save scan history to a JSON file
    """
    try:
        history_file = os.path.join('data', 'scan_history.json')
        
        # Create data directory if it doesn't exist
        if not os.path.exists('data'):
            os.makedirs('data')
        
        # Load existing history or create empty list
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                history = json.load(f)
        else:
            history = []
        
        # Add new scan data
        history.append(scan_data)
        
        # Save updated history
        with open(history_file, 'w') as f:
            json.dump(history, f, default=str)
            
    except Exception as e:
        logging.error(f"Error saving scan history: {str(e)}")

def get_feature_importance(model):
    """
    Get feature importance from the Random Forest part of the hybrid model
    """
    try:
        if hasattr(model, 'rf_model') and model.rf_model:
            importances = model.rf_model.feature_importances_
            feature_names = model.feature_names
            
            importance_dict = dict(zip(feature_names, importances))
            return sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        return []
    except Exception as e:
        logging.error(f"Error getting feature importance: {str(e)}")
        return []
