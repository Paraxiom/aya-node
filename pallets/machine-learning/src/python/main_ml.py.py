from .htms import HTMSEncoder
from .federated_learning import FederatedLearningCoordinator
from .anomaly_detection import AnomalyDetector

class MLPipeline:
    def __init__(self):
        self.encoder = HTMSEncoder()
        self.fl_coordinator = FederatedLearningCoordinator()
        self.anomaly_detector = AnomalyDetector()

    def process(self, data):
        encoded_data = self.encoder.encode(data)
        # Process through federated learning
        # Detect anomalies
        # Return results