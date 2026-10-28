import pandas as pd
import requests
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(DATA_DIR, "network_training_flows.csv")

KDD_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", 
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", 
    "root_shell", "su_attempt", "num_root", "num_file_creations", "num_shells", 
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", 
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", 
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", 
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", 
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", 
    "attack_type", "difficulty_level"
]

def build_network_dataset():
    print(f"[*] Downloading NSL-KDD Network Flow data...")
    try:
        response = requests.get(KDD_URL, timeout=30)
        response.raise_for_status()
        
        temp_file = os.path.join(DATA_DIR, "temp_kdd.txt")
        with open(temp_file, "w") as f:
            f.write(response.text)
            
        print("[*] Parsing network telemetry...")
        df = pd.read_csv(temp_file, names=COLUMNS)
        os.remove(temp_file)
        
        target_attacks = ['normal', 'neptune', 'satan']
        df = df[df['attack_type'].isin(target_attacks)].copy()
        
        label_mapping = {'normal': 0, 'neptune': 1, 'satan': 2}
        df['label'] = df['attack_type'].map(label_mapping)
        
        df = df.drop(columns=['attack_type', 'difficulty_level'])
        
        print("[*] Balancing Network Classes (Normal, Neptune, Satan)...")
        balanced_dfs = []
        for label in df['label'].unique():
            label_df = df[df['label'] == label]
            sampled = label_df.sample(min(len(label_df), 5000), random_state=42)
            balanced_dfs.append(sampled)
            
        final_df = pd.concat(balanced_dfs, ignore_index=True)
        final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n[+] Success! Network dataset saved to: {OUTPUT_FILE}")
        print(f"[+] Total unique network flows: {len(final_df)}")
        print(final_df['label'].value_counts())
        
    except Exception as e:
        print(f"[!] Failed to build network dataset: {e}")

if __name__ == "__main__":
    build_network_dataset()