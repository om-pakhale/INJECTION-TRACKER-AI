import pandas as pd
import joblib
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "training_payloads.csv")

MODEL_OUT = os.path.join(PROJECT_ROOT, "Models", "multiclass_model.pkl")
VEC_OUT = os.path.join(PROJECT_ROOT, "Models", "multiclass_vector.pkl")

def load_data():
    print(f"[*] Loading dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    df['payload'] = df['payload'].astype(str)
    df['label'] = df['label'].astype(int)
    return df['payload'], df['label']

def train_hyper_optimized_model():
    X, y = load_data()
    
    print("[*] Vectorizing with Advanced N-Grams (1 to 5) and Sublinear TF...")
    # Upgraded: Captures up to 5-char sequences. sublinear_tf=True normalizes repetitive payload spam.
    vectorizer = TfidfVectorizer(
        analyzer='char', 
        ngram_range=(1, 5), 
        max_features=25000, 
        sublinear_tf=True 
    )
    X_vec = vectorizer.fit_transform(X)
    
    print("[*] Splitting dataset (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_vec, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("[*] Training Uncapped Random Forest Model (This may take a minute)...")
    # Upgraded: 300 trees (more votes), max_depth=None allows trees to map complex payload logic perfectly.
    model = RandomForestClassifier(
        n_estimators=300, 
        max_depth=None, 
        min_samples_split=2,
        class_weight='balanced', 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Validation Phase
    print("\n[*] Running 5-Fold Cross-Validation for Robustness Check...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1_macro', n_jobs=-1)
    print(f"    -> Cross-Validation F1 Scores: {np.round(cv_scores, 4)}")
    print(f"    -> Mean Validation F1 Score:   {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    print("\n[*] Evaluating Final Test Data Accuracy...")
    y_pred = model.predict(X_test)
    
    target_names = ["Clean (0)", "SQLi (1)", "XSS (2)", "CMD_Inj (3)", "LFI (4)"]
    print("\n" + "="*60)
    print("                 CLASSIFICATION REPORT")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=target_names, digits=4))
    
    print(f"\nFinal Test Accuracy: {accuracy_score(y_test, y_pred) * 100:.4f}%")
    
    print(f"\n[*] Saving optimized model and vectorizer to {os.path.dirname(MODEL_OUT)}...")
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump(vectorizer, VEC_OUT, compress=3)
    joblib.dump(model, MODEL_OUT, compress=3)
    print("[+] Training complete! Artifacts compressed and saved.")

if __name__ == "__main__":
    train_hyper_optimized_model()