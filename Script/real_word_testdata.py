import pandas as pd
import random
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
INPUT_FILE = os.path.join(PROJECT_ROOT, "data", "training_payloads.csv")
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "data", "realworld_payloads.csv")

def wrap_payload(payload, label):
    """Wraps raw payloads in real-world web contexts (URLs, JSON, Headers)"""
    payload = str(payload).strip()
    
    # 1. Keep some payloads raw (don't wrap everything)
    if random.random() < 0.3:
        return payload
        
    contexts = [
        # URL Parameters
        f"https://api.target.com/v1/users?id={payload}&sort=desc",
        f"GET /search?q={payload} HTTP/1.1",
        f"/index.php?page={payload}",
        
        # JSON Bodies
        f'{{"username": "admin", "bio": "{payload}"}}',
        f'{{"data": ["1", "2", "{payload}"]}}',
        
        # HTTP Headers
        f"User-Agent: Mozilla/5.0 {payload}",
        f"Referer: https://google.com/{payload}",
        f"X-Forwarded-For: {payload}"
    ]
    
    return random.choice(contexts)

def generate_benign_traffic(target_count=5000):
    """Generates ultra-realistic benign web traffic to stop false positives."""
    benign = []
    endpoints = ["/api/v1/auth", "/users/profile", "/assets/logo.png", "/checkout/cart"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    
    while len(benign) < target_count:
        choice = random.randint(1, 4)
        if choice == 1:
            benign.append(f"{random.choice(methods)} {random.choice(endpoints)} HTTP/1.1")
        elif choice == 2:
            benign.append(f"https://www.google.com/search?q=normal+search+query+{random.randint(1,999)}")
        elif choice == 3:
            benign.append(f'{{"user_id": {random.randint(1000,9999)}, "action": "login", "success": true}}')
        else:
            benign.append(f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
    return benign

def build_realworld_dataset():
    print(f"[*] Loading raw dataset from {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    
    print("[*] Transforming raw payloads into real-world HTTP traffic...")
    # Wrap malicious payloads in context
    df['payload'] = df.apply(lambda row: wrap_payload(row['payload'], row['label']) if row['label'] != 0 else row['payload'], axis=1)
    
    print("[*] Injecting realistic JSON, URLs, and Headers into Clean (Label 0) traffic...")
    # Overwrite the old "single word" clean data with actual traffic structures
    real_benign = generate_benign_traffic(5000)
    
    # Remove old Label 0 and append the new realistic Label 0
    df = df[df['label'] != 0]
    benign_df = pd.DataFrame({'payload': real_benign, 'label': 0})
    df = pd.concat([df, benign_df], ignore_index=True)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"[*] Saving Real-World Dataset to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[+] Complete. Total payloads: {len(df)}")
    print(df['label'].value_counts())

if __name__ == "__main__":
    build_realworld_dataset()