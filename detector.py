import logging
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Try to import scikit-learn, but continue if it's not available
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    USE_SKLEARN = True
except ImportError:
    logger.warning("scikit-learn not available. Running in simulation mode.")
    USE_SKLEARN = False

class AnomalyDetector:
    def __init__(self):
        self.is_trained = False
        self.historical_data = []
        self.threshold = 0.7  # Default threshold
        
        if USE_SKLEARN:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,  # Expect about 5% of traffic to be anomalous
                random_state=42
            )
        else:
            self.model = None
            logger.info("Running anomaly detection in simulation mode without scikit-learn.")
    
    def train_model(self, data_points):
        """Train the anomaly detection model on historical data."""
        if not USE_SKLEARN:
            # In simulation mode, just pretend the model is trained
            self.is_trained = True
            logger.info("Simulation mode: Anomaly detection model 'trained' successfully.")
            return True
            
        if len(data_points) < 10:
            logger.warning("Not enough data points to train the model.")
            return False
        
        try:
            X = np.array(data_points)
            self.model.fit(X)
            self.is_trained = True
            logger.info("Anomaly detection model trained successfully.")
            return True
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {str(e)}")
            return False
    
    def detect_anomalies(self, traffic_data):
        """
        Detect anomalies in the provided network traffic data.
        
        Args:
            traffic_data: Dictionary containing network traffic statistics.
            
        Returns:
            list: List of detected anomalies.
        """
        anomalies = []
        
        try:
            # Check for PII/SPII leaks first - these are always anomalies
            for pii_detection in traffic_data.get('pii_detections', []):
                anomaly = {
                    'type': 'PII_LEAK',
                    'severity': 'HIGH',
                    'message': f"Potential PII leak detected: {pii_detection['pattern']}",
                    'source_ip': pii_detection['src_ip'],
                    'destination_ip': pii_detection['dst_ip'],
                    'port': pii_detection['dst_port']
                }
                anomalies.append(anomaly)
            
            for spii_detection in traffic_data.get('spii_detections', []):
                anomaly = {
                    'type': 'SPII_LEAK',
                    'severity': 'CRITICAL',
                    'message': f"Potential SPII leak detected: {spii_detection['pattern']}",
                    'source_ip': spii_detection['src_ip'],
                    'destination_ip': spii_detection['dst_ip'],
                    'port': spii_detection['dst_port']
                }
                anomalies.append(anomaly)
            
            # Now check for traffic anomalies 
            port_data = []
            for port, count in traffic_data.get('port_counts', {}).items():
                bytes_transferred = traffic_data.get('port_bytes', {}).get(port, 0)
                
                # Create feature vector for this port's traffic
                # [port, packet_count, bytes_transferred, bytes_per_packet]
                bytes_per_packet = bytes_transferred / count if count > 0 else 0
                port_data.append([
                    int(port), 
                    int(count), 
                    int(bytes_transferred), 
                    float(bytes_per_packet)
                ])
                
                # Add to historical data
                self.historical_data.append([
                    int(port), 
                    int(count), 
                    int(bytes_transferred), 
                    float(bytes_per_packet)
                ])
            
            # Limit historical data to last 1000 points
            if len(self.historical_data) > 1000:
                self.historical_data = self.historical_data[-1000:]
            
            # Train model if we have enough data points and it's not trained yet
            if not self.is_trained and len(self.historical_data) >= 50:
                self.train_model(self.historical_data)
            
            if USE_SKLEARN:
                # If scikit-learn is available and model is trained, use it to detect anomalies
                if self.is_trained and port_data:
                    X = np.array(port_data)
                    
                    # Get anomaly scores (-1 for anomalies, 1 for normal points)
                    scores = self.model.decision_function(X)
                    predictions = self.model.predict(X)
                    
                    # Process anomalies
                    for i, pred in enumerate(predictions):
                        if pred == -1:  # -1 indicates an anomaly
                            port, count, bytes_transferred, _ = port_data[i]
                            score = scores[i]
                            
                            # Determine severity based on anomaly score
                            severity = 'MEDIUM'
                            if score < -0.8:
                                severity = 'HIGH'
                            elif score > -0.5:
                                severity = 'LOW'
                            
                            anomaly = {
                                'type': 'TRAFFIC_ANOMALY',
                                'severity': severity,
                                'message': f"Unusual traffic detected on port {port}: {count} packets, {bytes_transferred} bytes",
                                'port': port,
                                'score': float(score)
                            }
                            anomalies.append(anomaly)
            else:
                # In simulation mode, occasionally generate random anomalies for demo purposes
                if self.is_trained and port_data and random.random() < 0.3:  # 30% chance of anomaly in sim mode
                    # Select a random port to flag as anomalous
                    if port_data:
                        anomaly_index = random.randint(0, len(port_data) - 1)
                        port, count, bytes_transferred, _ = port_data[anomaly_index]
                        
                        # Randomize severity
                        severity = random.choice(['LOW', 'MEDIUM', 'HIGH'])
                        score = random.uniform(-1.0, -0.1)
                        
                        anomaly = {
                            'type': 'TRAFFIC_ANOMALY',
                            'severity': severity,
                            'message': f"Unusual traffic detected on port {port}: {count} packets, {bytes_transferred} bytes",
                            'port': port,
                            'score': score
                        }
                        anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return []
    
    def update_threshold(self, new_threshold):
        """Update the anomaly detection threshold."""
        if 0 <= new_threshold <= 1:
            self.threshold = new_threshold
            return True
        return False
