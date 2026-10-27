import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(DATA_DIR, "training_payloads.csv")

SOURCES = {
    0: [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
    ],
    1: [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt",
        "https://raw.githubusercontent.com/PenTestical/sqli/master/hugeSQL.txt",
        "https://raw.githubusercontent.com/Proviesec/SQL-Injection-Payloads/main/error-based-sql-injection-payloads.txt",
        "https://raw.githubusercontent.com/Proviesec/SQL-Injection-Payloads/main/time-based-sql-injections-payloads.txt",
        "https://raw.githubusercontent.com/payload-box/sql-injection-payload-list/master/burp-intruder-payloads.txt"
    ],
    2: [
        "https://raw.githubusercontent.com/Proviesec/xss-payload-list/main/XSS_Payloads.txt",
        "https://raw.githubusercontent.com/Proviesec/xss-payload-list/main/xss-all-list.txt"
    ],
    3: [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt"
    ],
    4: [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt"
    ]
}

def get_resilient_session():
    """Builds an HTTP session that automatically retries dropped connections."""
    session = requests.Session()
    # Retry 5 times, backing off exponentially (1s, 2s, 4s, 8s) if the network drops
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def augment_sqli(sqli_list, target_count=5000):
    print(f"[*] Augmenting SQLi payloads from {len(sqli_list)} up to {target_count}...")
    augmented = set(sqli_list)
    spaces = [" ", "/**/", "%20", "%09"]
    comments = ["--", "#", "/*", ";\x00", " -- -", " #--"]
    sqli_list_indexed = list(sqli_list)
    
    while len(augmented) < target_count:
        base = random.choice(sqli_list_indexed)
        mutated = base + random.choice(spaces) + random.choice(comments)
        augmented.add(mutated)
        
    return list(augmented)

def wrap_payload(payload):
    payload = str(payload).strip()
    if random.random() < 0.3:
        return payload
        
    contexts = [
        f"https://api.target.com/v1/users?id={payload}&sort=desc",
        f"GET /search?q={payload} HTTP/1.1",
        f"/index.php?page={payload}",
        f'{{"username": "admin", "bio": "{payload}"}}',
        f'{{"data": ["1", "2", "{payload}"]}}',
        f"User-Agent: Mozilla/5.0 {payload}",
        f"Referer: https://google.com/{payload}",
        f"X-Forwarded-For: {payload}"
    ]
    return random.choice(contexts)

def generate_benign_traffic(target_count=5000):
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

def fetch_and_label_data():
    dataset = []
    session = get_resilient_session()
    print("[*] Starting dataset aggregation from GitHub (with auto-retry)...")
    for label, urls in SOURCES.items():
        label_count = 0
        for url in urls:
            try:
                print(f"    -> Fetching {url.split('/')[-1]} (Label: {label})")
                # Increased timeout to 60 seconds
                response = session.get(url, timeout=60)
                response.raise_for_status() 
                
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if len(line) > 1:
                        dataset.append({"payload": line, "label": label})
                        label_count += 1
            except Exception as e:
                print(f"    [!] Failed to fetch {url}: {e}")
        print(f"[+] Total raw payloads collected for Label {label}: {label_count}")
    return dataset

if __name__ == "__main__":
    raw_data = fetch_and_label_data()
    df = pd.DataFrame(raw_data)
    
    df = df.drop_duplicates()
    
    sqli_payloads = df[df['label'] == 1]['payload'].tolist()
    if len(sqli_payloads) < 5000 and len(sqli_payloads) > 0:
        expanded_sqli = augment_sqli(sqli_payloads, 5000)
        df = df[df['label'] != 1]
        augmented_df = pd.DataFrame({'payload': expanded_sqli, 'label': 1})
        df = pd.concat([df, augmented_df], ignore_index=True)
    
    print("\n[*] Transforming malicious payloads into real-world HTTP traffic...")
    df['payload'] = df.apply(lambda row: wrap_payload(row['payload']) if row['label'] != 0 else row['payload'], axis=1)

    print("[*] Generating highly realistic Benign (Clean) traffic...")
    real_benign = generate_benign_traffic(5000)
    df = df[df['label'] != 0] 
    benign_df = pd.DataFrame({'payload': real_benign, 'label': 0})
    df = pd.concat([df, benign_df], ignore_index=True)
    
    print("[*] Balancing dataset classes...")
    balanced_dfs = []
    for label in df['label'].unique():
        label_df = df[df['label'] == label]
        # Only sample up to what exists, to prevent crashing if a download still fails
        sampled = label_df.sample(min(len(label_df), 5000), random_state=42)
        balanced_dfs.append(sampled)
        
    balanced_df = pd.concat(balanced_dfs, ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    balanced_df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8')
    
    print(f"\n[+] Success! Context-Aware Dataset saved to: {OUTPUT_FILE}")
    print(f"[+] Total unique payloads: {len(balanced_df)}")
    print(balanced_df['label'].value_counts())