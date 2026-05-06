import os
import glob
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data", "cic_ids2017")

MODEL_PATH = os.path.join(BASE_DIR, "models", "network_attack_model.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "feature_columns.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "models", "model_metrics.joblib")


def load_all_csv_files():
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {DATA_DIR}")

    dataframes = []

    print("Loading CIC-IDS2017 CSV files...")

    for file_path in csv_files:
        print(f"Loading: {os.path.basename(file_path)}")

        df = pd.read_csv(file_path)
        df.columns = df.columns.str.strip()

        if "Label" not in df.columns:
            print(f"Skipping file without Label column: {file_path}")
            continue

        dataframes.append(df)

    if not dataframes:
        raise ValueError("No valid CSV files with Label column were found.")

    full_df = pd.concat(dataframes, ignore_index=True)

    print(f"\nCombined dataset shape: {full_df.shape}")

    return full_df


def clean_data(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    df = df.drop_duplicates()

    return df


def prepare_data(df):
    df = clean_data(df)

    X = df.drop("Label", axis=1)
    X = X.select_dtypes(include=["number"])

    X = X.replace([float("inf"), float("-inf")], 0)
    X = X.fillna(0)

    y = df["Label"].astype(str)

    processed_df = X.copy()
    processed_df["Label"] = y.values

    class_counts = processed_df["Label"].value_counts()

    print("\nOriginal class distribution:")
    print(class_counts)

    sampled_parts = []

    max_per_class = 10000
    min_required = 20

    for label, count in class_counts.items():
        label_df = processed_df[processed_df["Label"] == label]

        if count < min_required:
            print(f"Skipping class '{label}' because it has only {count} records.")
            continue

        sample_size = min(count, max_per_class)

        sampled_parts.append(
            label_df.sample(n=sample_size, random_state=42)
        )

    df_sampled = pd.concat(sampled_parts)
    df_sampled = df_sampled.sample(frac=1, random_state=42)

    X = df_sampled.drop("Label", axis=1)
    y = df_sampled["Label"]

    print("\nSampled class distribution:")
    print(y.value_counts())

    return X, y


def train():
    df = load_all_csv_files()
    X, y = prepare_data(df)

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    print("\nTraining multi-class IDS model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )
    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )
    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    print("\nModel evaluation:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")

    print("\nClassification report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    labels = list(model.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    feature_importance = pd.DataFrame({
        "feature": feature_columns,
        "importance": model.feature_importances_
    }).sort_values(by="importance", ascending=False)

    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "classes": labels,
        "confusion_matrix": cm,
        "feature_importance": feature_importance
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(feature_columns, FEATURES_PATH)
    joblib.dump(metrics, METRICS_PATH)

    print("\nModel saved successfully.")
    print(f"Features used: {len(feature_columns)}")
    print(f"Classes used: {labels}")


if __name__ == "__main__":
    train()