import joblib
import pandas

model = joblib.load('full_injection_model.pkl')
vector = joblib.load('full_vectorizer.pkl')
test_samples = 'http://testphp.vulnweb.com/listproducts.php?cat=1'
sample_vectors = vector.transform([test_samples])
results = model.predict(sample_vectors)
label = "MALICIOUS" if results == 1 else "CLEAN"
print(f"Payload: {test_samples} | Result: {label}")