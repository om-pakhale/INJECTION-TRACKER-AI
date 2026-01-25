import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
import joblib 

data =  pd.read_csv("SQLInjection_XSS_CommandInjection_MixDataset.1.0.0.csv")
df = pd.DataFrame(data)
df['label'] = df[['SQLInjection', 'XSS', 'CommandInjection']].max(axis=1)

vector = TfidfVectorizer(analyzer='char', ngram_range=(1, 3),max_features=5000)
X = vector.fit_transform(df['Sentence'].values.astype('U'))
Y = df['label']
print()
model = RandomForestClassifier(n_estimators=20, n_jobs=-1,verbose=1)
model.fit(X,Y)

test_payload = ["<svg/onload=alert(1)>"]
test_vector = vector.transform(test_payload)
prediction = model.predict(test_vector)

joblib.dump(model, 'full_injection_model.pkl')
joblib.dump(vector, 'full_vectorizer.pkl')
print(f"Is it malicious? {'YES' if prediction[0] == 1 else 'NO'}")

for payload, pred in zip(test_payload, prediction):
    # Adjust logic if your labels are strings like 'malicious'
    status = "MALICIOUS" if pred == 1 else "CLEAN"
    print(f"Payload: {payload} -> Result: {status}")
test_samples = [
    "Hello, how are you today?",                # Clean
    "SELECT * FROM users WHERE id=1 OR 1=1",    # SQL Injection
    "<script>document.cookie</script>",         # XSS
    "rm -rf /"                                  # Command Injection
]

sample_vectors = vector.transform(test_samples)
results = model.predict(sample_vectors)

for text, res in zip(test_samples, results):
    label = "MALICIOUS" if res == 1 else "CLEAN"
    print(f"Payload: {text} | Result: {label}")

