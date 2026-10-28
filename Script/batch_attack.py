import pandas as pd
import joblib
import os
import urllib.parse

# Define file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "training_payloads.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "Models", "multiclass_model.pkl")
VEC_PATH = os.path.join(PROJECT_ROOT, "Models", "multiclass_vector.pkl")

LABEL_MAP = {
    0: "Clean / Benign",
    1: "SQL Injection",
    2: "Cross-Site Scripting (XSS)",
    3: "Command Injection",
    4: "Path Traversal (LFI)"
}

def load_testing_environment():
    """Loads the dataset and the AI Engine."""
    print(f"[*] Loading Payload Database from {DATA_PATH}...")
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError("Dataset not found. Please run dataset.py first.")
    
    df = pd.read_csv(DATA_PATH)
    
    print("[*] Loading AI Defender Engine...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
        raise FileNotFoundError("Models not found. Please run train.py first.")
        
    vectorizer = joblib.load(VEC_PATH)
    model = joblib.load(MODEL_PATH)
    
    return df, vectorizer, model

def batch_test_urls():
    df, vectorizer, model = load_testing_environment()
    
   # now making batch of only 40 sample for testing
    test_sample = df.sample(40, random_state=42)
    
    print("\n" + "="*90)
    print(f"{'SIMULATED INJECTED URL':<60} | {'AI PREDICTION':<25}")
    print("="*90)
    
    successful_blocks = 0
    total_attacks = 0
    
    for index, row in test_sample.iterrows():
        raw_payload = str(row['payload'])
        true_label = row['label']
        
        encoded_payload = urllib.parse.quote(raw_payload)
        
        # Append the payload to a dummy URL 
        simulated_url = f"https://your-website.com/api/search?query={encoded_payload}"
        
        vec_input = vectorizer.transform([simulated_url])
        prediction = model.predict(vec_input)[0]
        
        display_url = simulated_url
        if len(display_url) > 57:
            display_url = display_url[:54] + "..."
            
        ai_verdict = LABEL_MAP[prediction]
        
        # Track accuracy for malicious payloads
        if true_label != 0:
            total_attacks += 1
            if prediction != 0:
                successful_blocks += 1
                
        print(f"{display_url:<60} | {ai_verdict:<25}")
        
    print("="*90)
    
    if total_attacks > 0:
        detection_rate = (successful_blocks / total_attacks) * 100
        print(f"\n[*] BATCH TEST COMPLETE")
        print(f"[*] AI successfully blocked {detection_rate:.2f}% of the URL-encoded attacks.")

if __name__ == "__main__":
    batch_test_urls()