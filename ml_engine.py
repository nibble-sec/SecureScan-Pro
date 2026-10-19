# ml_engine.py
import os
import sys
import json
import numpy as np

# ------------------------------------------------------------------
# 1. Try to import LightGBM (required for model loading)
# ------------------------------------------------------------------
try:
    import lightgbm as lgb
    LGB_AVAILABLE = True
except ImportError:
    LGB_AVAILABLE = False
    print("[ML] Warning: lightgbm not installed. ML scanning will be disabled.")

# ------------------------------------------------------------------
# 2. Add the path where features.py exists and import PEFeatureExtractor
# ------------------------------------------------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from features import PEFeatureExtractor
    FEATURES_AVAILABLE = True
except ImportError as e:
    FEATURES_AVAILABLE = False
    print(f"[ML] Warning: Could not import PEFeatureExtractor: {e}")

class MLScanner:
    def __init__(self, model_path="models/ember_model.txt", mapping_path="models/family_mapping.json"):
        """
        Initialize ML scanner:
        - Load LightGBM model (if available)
        - Load family name mapping
        - Initialize feature extractor
        """
        # Diagnostic prints (remove after debugging)
        abs_model_path = os.path.abspath(model_path)
        print(f"[ML] Looking for model at: {abs_model_path}")
        print(f"[ML] Model file exists: {os.path.exists(abs_model_path)}")
        print(f"[ML] LightGBM available: {LGB_AVAILABLE}")
        print(f"[ML] Feature extractor available: {FEATURES_AVAILABLE}")

        # Feature extractor (required)
        self.extractor = None
        if FEATURES_AVAILABLE:
            try:
                self.extractor = PEFeatureExtractor()
                print("[ML] PEFeatureExtractor initialized successfully.")
            except Exception as e:
                print(f"[ML] Error initializing PEFeatureExtractor: {e}")
                self.extractor = None

        # Load LightGBM model
        self.model = None
        if LGB_AVAILABLE and os.path.exists(model_path):
            try:
                self.model = lgb.Booster(model_file=model_path)
                print(f"[ML] Model loaded from {abs_model_path}")
            except Exception as e:
                print(f"[ML] Error loading model: {e}")
                self.model = None
        else:
            if not LGB_AVAILABLE:
                print("[ML] Cannot load model: lightgbm not installed.")
            elif not os.path.exists(model_path):
                print(f"[ML] Model file not found: {abs_model_path}")

        # Load family mapping (if exists)
        self.family_map = None
        if os.path.exists(mapping_path):
            try:
                with open(mapping_path, "r") as f:
                    self.family_map = json.load(f)
                print(f"[ML] Family mapping loaded from {mapping_path}")
            except Exception as e:
                print(f"[ML] Error loading family mapping: {e}")
        else:
            print(f"[ML] Family mapping not found at {mapping_path}. Using fallback.")
            self.family_map = {"0": "Benign", "1": "Malware"}

    def extract_features(self, filepath):
        """
        Extract EMBER feature vector from a PE file.
        Returns a numpy array of shape (1, 2560) or None on failure.
        """
        if self.extractor is None:
            return None
        try:
            with open(filepath, "rb") as f:
                bytez = f.read()

            if len(bytez) < 2 or bytez[:2] != b"MZ":
                print(f"[ML] Not a valid PE file: {filepath}")
                return None

            vector = self.extractor.feature_vector(bytez)  # returns (2568,)
            
            # FIX: Model expects 2560 features, but extractor gives 2568.
            # Take only the first 2560 (discard the extra 8, e.g., AuthenticodeSignature)
            if vector.shape[0] == 2568:
                vector = vector[:2560]
                print("[ML] Trimmed feature vector from 2568 to 2560 dimensions.")
            
            return vector.reshape(1, -1)
        except Exception as e:
            print(f"[ML] Feature extraction error for {filepath}: {e}")
            return None

    def scan_file(self, filepath):
        """
        Returns dict with:
            - 'score': float 0-100 (malicious probability)
            - 'family': str (predicted malware family)
            - 'error': str if any failure
        """
        if not os.path.isfile(filepath):
            return {"error": "File not found"}

        if self.model is None:
            return {"error": "ML model not loaded"}

        features = self.extract_features(filepath)
        if features is None:
            return {"error": "Feature extraction failed (non-PE file?)"}

        # Predict multi-class probabilities (array of length num_classes)
        try:
            probs = self.model.predict(features)[0]  # shape (num_classes,)
        except Exception as e:
            return {"error": f"Model prediction failed: {e}"}

        # Assume class 0 is "Benign"
        benign_prob = probs[0]
        malicious_score = (1.0 - benign_prob) * 100.0

        # Determine family (ignore benign class)
        probs_mal = probs.copy()
        probs_mal[0] = -1.0  # ignore benign class for family prediction
        top_class_id = str(np.argmax(probs_mal))

        if malicious_score < 30.0:
            family = "None (Benign)"
        else:
            family = self.family_map.get(top_class_id, "Unknown Malware Family")

        return {"score": float(malicious_score), "family": family}
