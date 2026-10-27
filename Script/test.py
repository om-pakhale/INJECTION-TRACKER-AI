import pandas as pd
import joblib
import os
from sklearn.metrics import classification_report, accuracy_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "realworld_payloads.csv")

MODEL_PATH = os.path.join(PROJECT_ROOT, "Models", "multiclass_model.pkl")
VEC_PATH = os.path.join(PROJECT_ROOT, "Models", "multiclass_vector.pkl")

def evaluate_model_on_realworld():
    print(f"[*] Loading Real-World Test Dataset from {DATA_PATH}...")
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError("Real-world dataset not found! Run realworld_dataset.py first.")
    
    df = pd.read_csv(DATA_PATH)
    df['payload'] = df['payload'].astype(str)
    df['label'] = df['label'].astype(int)
    
    X_test_raw = df['payload']
    y_test = df['label']
    
    print("[*] Loading Existing AI Engine (Trained on Raw Data)...")
    vectorizer = joblib.load(VEC_PATH)
    model = joblib.load(MODEL_PATH)
    
    print("[*] Vectorizing Real-World Payloads...")
    X_test_vec = vectorizer.transform(X_test_raw)
    
    print("[*] Running Predictions...")
    y_pred = model.predict(X_test_vec)
    
    target_names = ["Clean (0)", "SQLi (1)", "XSS (2)", "CMD_Inj (3)", "LFI (4)"]
    print("\n" + "="*60)
    print("      REAL-WORLD STRESS TEST CLASSIFICATION REPORT")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=target_names, digits=4))
    
    print(f"\nReal-World Test Accuracy: {accuracy_score(y_test, y_pred) * 100:.4f}%")
    
    # Let's find exactly where it failed worst
    df['prediction'] = y_pred
    false_positives = df[(df['label'] == 0) & (df['prediction'] != 0)]
    
    print("\n[*] Sample False Positives (Clean traffic flagged as attacks):")
    for _, row in false_positives.head(5).iterrows():
        print(f"  -> Predicted {target_names[row['prediction']]}: {row['payload'][:80]}")

if __name__ == "__main__":
    evaluate_model_on_realworld()