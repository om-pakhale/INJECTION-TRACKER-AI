import joblib
import pandas
import streamlit as st
from urllib.parse import urlparse, unquote

@st.cache_resource
def extract_threat_zone(data):
    if data.startswith(('http://', 'https://')):
        data = unquote(data).replace('+', ' ')
        parsed = urlparse(data)
    
        threat_zone = parsed.path + "?" + parsed.query
        return threat_zone.lower()
    return data.lower()


model = joblib.load('full_injection_model.pkl')
vector = joblib.load('full_vectorizer.pkl')

st.header("INJECTION TRACKER")
data = st.text_input("Enter your Url")
if data:
    input = extract_threat_zone(data)
    sample_vectors = vector.transform([input])
    probabilities = model.predict_proba(sample_vectors)[0]
    malicious_score = probabilities[1] 
    if malicious_score > 0.98: 
        st.error(f"MALICIOUS (Confidence: {malicious_score:.2%})")
    else:
        st.success(f"CLEAN (Confidence: {1 - malicious_score:.2%})")