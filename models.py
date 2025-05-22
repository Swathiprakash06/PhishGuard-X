from app import db
from datetime import datetime

class ScanHistory(db.Model):
    """Model for storing URL scan history"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    feature_data = db.Column(db.Text, nullable=False)  # JSON string of features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanHistory {self.url}>'
