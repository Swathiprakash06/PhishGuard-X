import os
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from feature_extraction import extract_features_from_dataset
from model import HybridPhishingDetector

def train_model(phishing_data_path, legitimate_data_path):
    """
    Train a new phishing detection model
    
    Args:
        phishing_data_path (str): Path to phishing URLs dataset
        legitimate_data_path (str): Path to legitimate URLs dataset
        
    Returns:
        HybridPhishingDetector: Trained model
    """
    logging.info("Starting model training...")
    
    try:
        # Load datasets
        logging.info(f"Loading phishing dataset from {phishing_data_path}")
        phishing_df = pd.read_csv(phishing_data_path)
        phishing_df['label'] = 1  # 1 for phishing
        
        logging.info(f"Loading legitimate dataset from {legitimate_data_path}")
        legitimate_df = pd.read_csv(legitimate_data_path)
        legitimate_df['label'] = 0  # 0 for legitimate
        
        # Combine datasets
        df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
        
        # Shuffle the data
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Extract URLs for LSTM training
        urls = df['Domain'].tolist()
        
        # Extract features and get labels
        logging.info("Extracting features from data...")
        X, y = extract_features_from_dataset(df)
        
        # Drop columns with all NaN or constant values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.dropna(axis=1, how='all')
        X = X.fillna(0)
        
        # Select relevant features, excluding Domain and any non-numeric columns
        numeric_columns = X.select_dtypes(include=['number']).columns
        X = X[numeric_columns]
        
        # Drop duplicate columns
        X = X.loc[:, ~X.columns.duplicated()]
        
        # Split data
        X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
            X, y, urls, test_size=0.2, random_state=42
        )
        
        # Create and train the model
        logging.info("Training hybrid model...")
        model = HybridPhishingDetector()
        model.train(X_train, y_train, urls_train)
        
        # Evaluate model
        logging.info("Evaluating model performance...")
        evaluate_model(model, X_test, y_test, urls_test)
        
        return model
    
    except Exception as e:
        logging.error(f"Error during model training: {str(e)}")
        # Return a basic model if training fails
        return HybridPhishingDetector()

def evaluate_model(model, X_test, y_test, urls_test):
    """
    Evaluate model performance
    
    Args:
        model (HybridPhishingDetector): Model to evaluate
        X_test (pandas.DataFrame): Test features
        y_test (pandas.Series): Test labels
        urls_test (list): Test URLs
    """
    try:
        predictions = []
        for i, row in X_test.iterrows():
            # Extract the URL at the same index from urls_test
            url = urls_test[i] if i < len(urls_test) else ""
            
            # Create a features dictionary with the URL
            features = {'url': url}
            
            # Add other features
            for col in X_test.columns:
                features[col] = row[col]
            
            # Make prediction
            result = model.predict(features)
            predictions.append(1 if result['is_phishing'] else 0)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, zero_division=0)
        recall = recall_score(y_test, predictions, zero_division=0)
        f1 = f1_score(y_test, predictions, zero_division=0)
        
        logging.info(f"Model Evaluation Results:")
        logging.info(f"Accuracy: {accuracy:.4f}")
        logging.info(f"Precision: {precision:.4f}")
        logging.info(f"Recall: {recall:.4f}")
        logging.info(f"F1 Score: {f1:.4f}")
        
        # Save metrics
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        # Create data directory if it doesn't exist
        if not os.path.exists('data'):
            os.makedirs('data')
        
        # Save metrics to a file
        metrics_file = os.path.join('data', 'model_metrics.txt')
        with open(metrics_file, 'w') as f:
            for metric, value in metrics.items():
                f.write(f"{metric}: {value:.4f}\n")
    
    except Exception as e:
        logging.error(f"Error evaluating model: {str(e)}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Define paths to datasets
    phishing_data_path = os.path.join('attached_assets', 'phishing-urls.csv')
    legitimate_data_path = os.path.join('attached_assets', 'legitimate-urls.csv')
    
    # Train the model
    model = train_model(phishing_data_path, legitimate_data_path)
    
    # Save the model
    model_path = os.path.join('models', 'hybrid_phishing_detector.pkl')
    
    # Create models directory if it doesn't exist
    if not os.path.exists('models'):
        os.makedirs('models')
    
    model.save(model_path)
    logging.info(f"Model saved to {model_path}")
