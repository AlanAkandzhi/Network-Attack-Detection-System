import os
import joblib
import pandas as pd


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "models", "network_attack_model.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "feature_columns.joblib")


class MLService:
    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError("Model file not found. Train the model first.")

        if not os.path.exists(FEATURES_PATH):
            raise FileNotFoundError("Feature columns file not found.")

        self.model = joblib.load(MODEL_PATH)
        self.feature_columns = joblib.load(FEATURES_PATH)

        if hasattr(self.model, "classes_"):
            self.classes = list(self.model.classes_)
        else:
            self.classes = []

    def prepare_dataframe(self, records):
        df = pd.DataFrame(records)

        df.columns = df.columns.str.strip()

        for column in self.feature_columns:
            if column not in df.columns:
                df[column] = 0

        df = df[self.feature_columns]

        df = df.replace([float("inf"), float("-inf")], 0)
        df = df.fillna(0)

        return df

    def get_severity(self, prediction):
        high_risk_attacks = [
            "DDoS",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS Slowloris",
            "DoS Slowhttptest",
            "Heartbleed",
            "Infiltration"
        ]

        medium_risk_attacks = [
            "PortScan",
            "Bot",
            "FTP-Patator",
            "SSH-Patator",
            "Web Attack � Brute Force",
            "Web Attack � XSS",
            "Web Attack � Sql Injection"
        ]

        if prediction == "BENIGN":
            return "LOW"

        if prediction in high_risk_attacks:
            return "HIGH"

        if prediction in medium_risk_attacks:
            return "MEDIUM"

        return "UNKNOWN"

    def predict_batch(self, records):
        df = self.prepare_dataframe(records)

        predictions = self.model.predict(df)

        probabilities = None

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(df)

        results = []

        for index, prediction in enumerate(predictions):
            prediction = str(prediction)

            confidence = None
            probability_distribution = {}

            if probabilities is not None:
                row_probabilities = probabilities[index]

                confidence = round(float(row_probabilities.max()), 4)

                for class_name, probability in zip(self.classes, row_probabilities):
                    probability_distribution[str(class_name)] = round(float(probability), 4)

            results.append({
                "prediction": prediction,
                "confidence": confidence,
                "severity": self.get_severity(prediction),
                "probabilities": probability_distribution
            })

        return results