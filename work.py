import joblib
import pandas

model = joblib.load('full_injection_model.pkl')
vector = joblib.load('full_vectorizer.pkl')
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