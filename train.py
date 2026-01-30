import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
import joblib 
from urllib.parse import urlparse , unquote
def expert_normalize(text):
    text = unquote(text)
    
    if text.startswith(('http://', 'https://')):
        parsed = urlparse(text)
        text = parsed.path + "?" + parsed.query
        
    return text.lower()


data =  pd.read_csv("SQLInjection_XSS_CommandInjection_MixDataset.1.0.0.csv")
df = pd.DataFrame(data)
df['label'] = df[['SQLInjection', 'XSS', 'CommandInjection']].max(axis=1)

vector = TfidfVectorizer(analyzer='char',ngram_range=(1, 3), max_features=20000,lowercase=True)
benign_urls = [
    "https://leetcode.com/problems/two-sum/",
    "https://www.linkedin.com/feed/",
    "https://github.com/trending",
    "https://google.com/search?q=python+code",
    "https://stackoverflow.com/questions",
    "https://www.wikipedia.org/",
    "/problems/two-sum/?",  
    "/feed/?"               
]

df_benign = pd.DataFrame({"Sentence": benign_urls, "label": 0})

df_final = pd.concat([df] + [df_benign] * 500, ignore_index=True)
df_final['Sentence'] = df_final['Sentence'].apply(expert_normalize)
X = vector.fit_transform(df_final['Sentence'].values.astype('U'))
Y = df_final['label']

model = RandomForestClassifier(n_estimators=100,n_jobs=-1,class_weight='balanced',verbose=1)
print("Tranning Model...")
model.fit(X,Y)

test_payload = ["<svg/onload=alert(1)>"]
test_vector = vector.transform(test_payload)
prediction = model.predict(test_vector)

joblib.dump(model, 'full_injection_model.pkl')
joblib.dump(vector, 'full_vectorizer.pkl')
print(f"Is it malicious? {'YES' if prediction[0] == 1 else 'NO'}")

for payload, pred in zip(test_payload, prediction):
    status = "MALICIOUS" if pred == 1 else "CLEAN"
    print(f"Payload: {payload} -> Result: {status}")


