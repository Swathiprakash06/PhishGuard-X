import pickle
import logging
import numpy as np
import pandas as pd
import os
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Set up TensorFlow error logging and environment variables
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logging

# Try to import TensorFlow, but have a fallback if it fails
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model as keras_load_model
    from tensorflow.keras.layers import Dense, LSTM, Embedding, Dropout
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TF_AVAILABLE = True
except (ImportError, TypeError) as e:
    logging.warning(f"TensorFlow import failed: {str(e)}. Using RandomForest only.")
    TF_AVAILABLE = False

class HybridPhishingDetector:
    """
    Hybrid model combining LSTM and Random Forest for phishing URL detection
    """
    
    def __init__(self):
        """Initialize the hybrid model"""
        self.rf_model = None
        self.lstm_model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.tokenizer = None
        self.max_length = 100
        self.lstm_weight = 0.5  # Weight for LSTM model in the ensemble
        
    def preprocess_url_for_lstm(self, url):
        """
        Convert URL to sequence for LSTM
        
        Args:
            url (str): URL to preprocess
            
        Returns:
            numpy.ndarray: Padded sequence for LSTM
        """
        if not TF_AVAILABLE:
            # Return dummy data if TensorFlow is not available
            logging.warning("TensorFlow not available. Cannot preprocess URL for LSTM.")
            return np.zeros((1, self.max_length))
            
        # Convert URL to character indices
        if not self.tokenizer:
            # Create a simple character-level tokenizer if not available
            chars = list("abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
            self.tokenizer = {c: i+1 for i, c in enumerate(chars)}
        
        # Convert to sequence
        sequence = [self.tokenizer.get(c, 0) for c in url.lower()]
        
        # Pad sequence
        padded = pad_sequences([sequence], maxlen=self.max_length, padding='post')
        
        return padded
        
    def create_lstm_model(self, vocab_size=75, embedding_dim=32):
        """
        Create LSTM model for URL classification
        
        Args:
            vocab_size (int): Size of vocabulary
            embedding_dim (int): Dimension of embedding
            
        Returns:
            tensorflow.keras.models.Sequential: LSTM model or None if TF not available
        """
        if not TF_AVAILABLE:
            logging.warning("TensorFlow not available. Cannot create LSTM model.")
            return None
            
        try:
            model = Sequential([
                Embedding(input_dim=vocab_size+1, output_dim=embedding_dim, input_length=self.max_length),
                LSTM(64, return_sequences=True),
                Dropout(0.2),
                LSTM(32),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                loss='binary_crossentropy',
                optimizer='adam',
                metrics=['accuracy']
            )
            
            return model
        except Exception as e:
            logging.error(f"Error creating LSTM model: {str(e)}")
            return None
    
    def train(self, X, y, urls):
        """
        Train the hybrid model
        
        Args:
            X (pandas.DataFrame): Feature matrix
            y (pandas.Series): Target labels
            urls (list): List of URLs for LSTM training
            
        Returns:
            self: Trained model
        """
        try:
            # Log all features available for training
            logging.info(f"Training with {len(X.columns)} features: {X.columns.tolist()}")
            
            # Store feature names
            self.feature_names = X.columns.tolist()
            
            # Scale features for Random Forest
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Random Forest
            logging.info("Training Random Forest model...")
            self.rf_model = RandomForestClassifier(
                n_estimators=100, 
                max_depth=20,
                random_state=42
            )
            self.rf_model.fit(X_scaled, y)
            rf_accuracy = self.rf_model.score(X_scaled, y)
            logging.info(f"Random Forest accuracy: {rf_accuracy:.4f}")
            
            # Check if TensorFlow is available before attempting LSTM training
            if not TF_AVAILABLE:
                logging.warning("TensorFlow not available. Using Random Forest only.")
                self.lstm_weight = 0  # Only use Random Forest
                return self
                
            # Prepare data for LSTM
            logging.info("Preparing data for LSTM model...")
            X_lstm = np.array([self.preprocess_url_for_lstm(url)[0] for url in urls])
            
            # Train LSTM
            logging.info("Training LSTM model...")
            self.lstm_model = self.create_lstm_model()
            
            # Check if LSTM model creation was successful
            if self.lstm_model is None:
                logging.warning("LSTM model creation failed. Using Random Forest only.")
                self.lstm_weight = 0  # Only use Random Forest
                return self
                
            # Use early stopping to prevent overfitting
            early_stop = tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=3,
                restore_best_weights=True
            )
            
            # Train with validation split
            history = self.lstm_model.fit(
                X_lstm, y,
                epochs=10,
                batch_size=64,
                validation_split=0.2,
                callbacks=[early_stop],
                verbose=1
            )
            
            # Get LSTM accuracy
            _, lstm_accuracy = self.lstm_model.evaluate(X_lstm, y, verbose=0)
            logging.info(f"LSTM accuracy: {lstm_accuracy:.4f}")
            
            # Adjust model weights based on performance
            if lstm_accuracy > rf_accuracy:
                self.lstm_weight = 0.7
            else:
                self.lstm_weight = 0.3
                
            logging.info(f"Final model weights - LSTM: {self.lstm_weight}, RF: {1-self.lstm_weight}")
            
            return self
            
        except Exception as e:
            logging.error(f"Error training hybrid model: {str(e)}")
            # Fallback to just Random Forest if LSTM fails
            if X is not None and y is not None:
                if not self.feature_names:
                    self.feature_names = X.columns.tolist()
                if self.rf_model is None:
                    X_scaled = self.scaler.fit_transform(X)
                    self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
                    self.rf_model.fit(X_scaled, y)
                self.lstm_weight = 0  # Only use Random Forest
            return self
    
    def predict(self, features):
        """
        Make prediction using the hybrid model
        
        Args:
            features (dict): URL features
            
        Returns:
            dict: Prediction result
        """
        try:
            # Extract URL from features if present
            url = features.get('url', '')
            
            # Convert features to DataFrame
            if isinstance(features, dict):
                # Keep only features that are in feature_names
                if self.feature_names:
                    # Extract only features that were present during training
                    features_subset = {}
                    for feature in self.feature_names:
                        if feature in features:
                            features_subset[feature] = features[feature]
                        else:
                            # If a feature from training is missing in current features, set it to 0
                            features_subset[feature] = 0
                    
                    # Create DataFrame with only the features used during training
                    X = pd.DataFrame([features_subset])
                else:
                    X = pd.DataFrame([features])
            else:
                # If features is a DataFrame, ensure it has the same columns as during training
                if self.feature_names:
                    # Filter existing columns to match training features
                    common_features = [col for col in self.feature_names if col in features.columns]
                    # Get missing features from training
                    missing_features = [col for col in self.feature_names if col not in features.columns]
                    
                    # First select the common features
                    X = features[common_features].copy()
                    
                    # Then add missing features as zero columns
                    for feature in missing_features:
                        X[feature] = 0
                    
                    # Make sure columns are in the same order as during training
                    X = X[self.feature_names]
                else:
                    X = features
            
            # Initialize predictions
            rf_prob = 0
            lstm_prob = 0
            
            # Random Forest prediction
            if self.rf_model is not None:
                X_scaled = self.scaler.transform(X)
                rf_prob = self.rf_model.predict_proba(X_scaled)[0, 1]
            
            # LSTM prediction - only attempt if TensorFlow is available
            if TF_AVAILABLE and self.lstm_model is not None and url:
                try:
                    # Preprocess URL for LSTM
                    X_lstm = self.preprocess_url_for_lstm(url)
                    lstm_prob = self.lstm_model.predict(X_lstm)[0, 0]
                except Exception as lstm_err:
                    # Log the error but continue with RF prediction
                    logging.warning(f"LSTM prediction failed: {str(lstm_err)}. Using Random Forest only.")
                    lstm_prob = 0
                    self.lstm_weight = 0  # Only use Random Forest for this prediction
            
            # Combine predictions - only use LSTM if it returned a valid result
            if TF_AVAILABLE and self.lstm_model is not None and url and lstm_prob > 0:
                final_prob = self.lstm_weight * lstm_prob + (1 - self.lstm_weight) * rf_prob
            else:
                final_prob = rf_prob
            
            # Determine if it's phishing based on threshold
            # Using a lower threshold (0.3) to be more sensitive to potential phishing URLs
            is_phishing = final_prob >= 0.3
            
            # Return prediction
            return {
                'is_phishing': bool(is_phishing),
                'confidence': float(final_prob),
                'rf_confidence': float(rf_prob),
                'lstm_confidence': float(lstm_prob) if TF_AVAILABLE and self.lstm_model is not None and url and lstm_prob > 0 else 0,
                'threshold': 0.3  # Include the threshold in the response for transparency
            }
            
        except Exception as e:
            logging.error(f"Error making prediction: {str(e)}")
            # Try to make a very simple prediction based on domain features if possible
            try:
                # Check if it's a paypal-security domain with suspicious TLD
                url_lower = url.lower() if url else ""
                
                # First check if it's a legitimate known domain
                legitimate_domains = [
                    'paypal.com', 'apple.com', 'microsoft.com', 'amazon.com', 
                    'netflix.com', 'facebook.com', 'google.com', 'bankofamerica.com',
                    'chase.com', 'wellsfargo.com', 'citi.com', 'gmail.com',
                    'yahoo.com', 'live.com', 'outlook.com', 'ebay.com'
                ]
                
                # Extract the main domain from the URL
                from urllib.parse import urlparse
                try:
                    parsed_url = urlparse(url_lower)
                    domain = parsed_url.netloc
                    if not domain and '/' in url_lower:
                        # Handle cases without http:// prefix
                        domain = url_lower.split('/')[0]
                        
                    # Check for legitimate domains - consider subdomain structure 
                    if any(domain.endswith(f".{legit_domain}") or domain == legit_domain for legit_domain in legitimate_domains):
                        logging.info(f"URL recognized as legitimate domain: {domain}")
                        return {
                            'is_phishing': False, 
                            'confidence': 0.05, 
                            'rf_confidence': 0.0, 
                            'lstm_confidence': 0.0,
                            'threshold': 0.3,
                            'fallback_detection': True,
                            'legitimate_domain': True
                        }
                except Exception as domain_err:
                    logging.error(f"Error checking legitimate domains: {str(domain_err)}")
                
                if (
                    # URL contains suspicious patterns even without model
                    ('paypal' in url_lower and 'paypal.com' not in url_lower) or
                    ('security' in url_lower and 'alert' in url_lower) or
                    any(domain in url_lower for domain in ['apple', 'microsoft', 'amazon', 'netflix', 'facebook', 'google', 'bank']) and
                    any(tld in url_lower for tld in ['.xyz', '.top', '.info', '.site', '.online', '.fit', '.tk', '.ga', '.ml', '.cf', '.gq'])
                ):
                    logging.info("Fallback detection: URL matched basic suspicious patterns")
                    return {
                        'is_phishing': True, 
                        'confidence': 0.85, 
                        'rf_confidence': 0.0, 
                        'lstm_confidence': 0.0,
                        'threshold': 0.3,
                        'fallback_detection': True
                    }
                
                # Perform some basic heuristic checks for common phishing patterns
                suspicious_signals = 0
                
                # Check for IP addresses
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                    suspicious_signals += 3
                
                # Check for suspicious TLDs
                for tld in ['.xyz', '.top', '.info', '.site', '.online', '.fit', '.tk', '.ga', '.ml', '.cf', '.gq']:
                    if tld in url_lower:
                        suspicious_signals += 2
                        break
                
                # Check for suspicious words
                for word in ['secure', 'account', 'login', 'signin', 'banking', 'confirm', 'password', 'verify']:
                    if word in url_lower:
                        suspicious_signals += 1
                
                # Check for brand names in non-brand domains
                for brand in ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook', 'google', 'bank']:
                    if brand in url_lower and f"{brand}.com" not in url_lower:
                        suspicious_signals += 3
                
                # Check for lots of special characters, but be smarter about it
                # Don't count normal URL path components like slashes and periods as suspicious
                special_char_count = sum(1 for c in url if c in '-_~[]@!$\'()*+;=%')
                # Only count as suspicious if there's an unusually high number
                if special_char_count > 8:
                    suspicious_signals += 1
                
                # Make a decision based on suspicious signals
                is_phishing = suspicious_signals >= 3
                confidence = min(0.7, suspicious_signals / 10)
                
                return {
                    'is_phishing': is_phishing, 
                    'confidence': float(confidence), 
                    'rf_confidence': 0.0, 
                    'lstm_confidence': 0.0,
                    'threshold': 0.3,
                    'fallback_detection': True
                }
                
            except Exception as fallback_error:
                logging.error(f"Even fallback detection failed: {str(fallback_error)}")
                # Return default prediction as last resort
                return {'is_phishing': False, 'confidence': 0.0, 'rf_confidence': 0.0, 'lstm_confidence': 0.0, 'fallback_detection': True}
    
    def get_feature_importance(self):
        """
        Get feature importance from Random Forest
        
        Returns:
            dict: Feature importance
        """
        if self.rf_model is not None and self.feature_names is not None:
            importance = self.rf_model.feature_importances_
            return dict(zip(self.feature_names, importance))
        return {}
    
    def save(self, filepath):
        """
        Save the model to a file
        
        Args:
            filepath (str): Path to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Save LSTM model separately if it exists
            if self.lstm_model is not None:
                lstm_path = filepath.replace('.pkl', '_lstm.h5')
                self.lstm_model.save(lstm_path)
                # Set to None temporarily for pickling
                lstm_model_tmp = self.lstm_model
                self.lstm_model = None
            
            # Save the rest of the model
            with open(filepath, 'wb') as f:
                pickle.dump(self, f)
            
            # Restore LSTM model if it existed
            if 'lstm_model_tmp' in locals():
                self.lstm_model = lstm_model_tmp
            
            return True
        
        except Exception as e:
            logging.error(f"Error saving model: {str(e)}")
            return False
    
    @classmethod
    def load(cls, filepath):
        """
        Load the model from a file
        
        Args:
            filepath (str): Path to load the model from
            
        Returns:
            HybridPhishingDetector: Loaded model
        """
        try:
            # Load the main model
            with open(filepath, 'rb') as f:
                model = pickle.load(f)
            
            # Load LSTM model if TensorFlow is available and LSTM model exists
            if TF_AVAILABLE:
                lstm_path = filepath.replace('.pkl', '_lstm.h5')
                if os.path.exists(lstm_path):
                    try:
                        model.lstm_model = keras_load_model(lstm_path)
                        logging.info("LSTM model loaded successfully")
                    except Exception as e:
                        logging.warning(f"Failed to load LSTM model: {str(e)}. Using Random Forest only.")
                        model.lstm_model = None
                        model.lstm_weight = 0
            else:
                logging.warning("TensorFlow not available. Using Random Forest only.")
                model.lstm_model = None
                model.lstm_weight = 0
            
            return model
        
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
            # Return a new instance if loading fails
            return cls()

import os  # Added missing import
