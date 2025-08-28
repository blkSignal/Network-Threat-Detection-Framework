#!/usr/bin/env python3
"""
Machine Learning Enhancement for Goliath Systems

Provides ML-powered threat detection capabilities:
- Anomaly detection
- Pattern recognition
- Predictive analytics
- Feature engineering
"""

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
from typing import Dict, List, Tuple, Optional

class MLThreatDetector:
    """Machine learning enhanced threat detection."""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.anomaly_detector = None
        self.classifier = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Ensure model directory exists
        os.makedirs(model_path, exist_ok=True)
    
    def extract_features(self, data: List[Dict]) -> np.ndarray:
        """Extract numerical features from threat data."""
        if not data:
            raise ValueError("Data cannot be empty")
        
        features = []
        
        for item in data:
            feature_vector = [
                item.get('entropy', 0.0),
                item.get('length', 0),
                item.get('digit_ratio', 0.0),
                item.get('consonant_ratio', 0.0),
                item.get('base64_score', 0.0),
                item.get('connection_count', 0),
                item.get('periodicity_score', 0.0),
                item.get('variance_score', 0.0)
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def train_anomaly_detector(self, data: List[Dict], contamination: float = 0.1):
        """Train isolation forest for anomaly detection."""
        if len(data) < 10:
            raise ValueError("Insufficient data for training. Need at least 10 samples.")
        
        features = self.extract_features(data)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train isolation forest
        self.anomaly_detector = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.anomaly_detector.fit(features_scaled)
        self.is_trained = True
        
        print(f"Anomaly detector trained on {len(features)} samples")
    
    def detect_anomalies(self, data: List[Dict]) -> List[bool]:
        """Detect anomalies in new data."""
        if not self.is_trained:
            raise ValueError("Model must be trained before detection")
        
        features = self.extract_features(data)
        features_scaled = self.scaler.transform(features)
        
        # -1 for anomalies, 1 for normal
        predictions = self.anomaly_detector.predict(features_scaled)
        
        # Convert to boolean (True for anomalies)
        return [pred == -1 for pred in predictions]
    
    def train_classifier(self, data: List[Dict], labels: List[str]):
        """Train random forest classifier for threat classification."""
        features = self.extract_features(data)
        
        if len(features) < 20:
            print("Insufficient data for training. Need at least 20 samples.")
            return
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        
        self.classifier.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.classifier.predict(X_test_scaled)
        print("Classification Report:")
        print(classification_report(y_test, y_pred))
        
        self.is_trained = True
    
    def classify_threats(self, data: List[Dict]) -> List[str]:
        """Classify threats using trained model."""
        if not self.is_trained:
            raise ValueError("Model must be trained before classification")
        
        features = self.extract_features(data)
        features_scaled = self.scaler.transform(features)
        
        predictions = self.classifier.predict(features_scaled)
        return predictions.tolist()
    
    def save_models(self):
        """Save trained models to disk."""
        if self.anomaly_detector:
            joblib.dump(self.anomaly_detector, 
                       os.path.join(self.model_path, 'anomaly_detector.pkl'))
        
        if self.classifier:
            joblib.dump(self.classifier, 
                       os.path.join(self.model_path, 'classifier.pkl'))
        
        joblib.dump(self.scaler, 
                   os.path.join(self.model_path, 'scaler.pkl'))
        
        print("Models saved successfully")
    
    def load_models(self):
        """Load trained models from disk."""
        try:
            self.anomaly_detector = joblib.load(
                os.path.join(self.model_path, 'anomaly_detector.pkl'))
            self.classifier = joblib.load(
                os.path.join(self.model_path, 'classifier.pkl'))
            self.scaler = joblib.load(
                os.path.join(self.model_path, 'scaler.pkl'))
            self.is_trained = True
            print("Models loaded successfully")
        except FileNotFoundError:
            print("No saved models found. Train models first.")
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained classifier."""
        if not self.is_trained or not self.classifier:
            return {}
        
        feature_names = [
            'entropy', 'length', 'digit_ratio', 'consonant_ratio',
            'base64_score', 'connection_count', 'periodicity_score', 'variance_score'
        ]
        
        importance = self.classifier.feature_importances_
        return dict(zip(feature_names, importance))

# Example usage and testing
if __name__ == "__main__":
    # Create sample data
    sample_data = [
        {'entropy': 3.5, 'length': 15, 'digit_ratio': 0.2, 'consonant_ratio': 0.6,
         'base64_score': 0.1, 'connection_count': 5, 'periodicity_score': 0.8, 'variance_score': 0.7},
        {'entropy': 4.2, 'length': 25, 'digit_ratio': 0.8, 'consonant_ratio': 0.3,
         'base64_score': 0.9, 'connection_count': 20, 'periodicity_score': 0.9, 'variance_score': 0.9},
        # Add more samples...
    ]
    
    # Initialize ML detector
    ml_detector = MLThreatDetector()
    
    # Train models
    ml_detector.train_anomaly_detector(sample_data)
    
    # Save models
    ml_detector.save_models()
