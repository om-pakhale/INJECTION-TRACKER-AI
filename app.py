import joblib
import pandas
import streamlit as st


model = joblib.load('full_injection_model.pkl')
vector = joblib.load('full_vectorizer.pkl')

st.header("INJECTION TRACKER")
data = st.text_input("Enter your Url")
if data:
    sample_vectors = vector.transform(data)
    results = model.predict(sample_vectors)
    if results==1:
        st.warning(f"{data} is MALICIOUS")
    else:
        st.write(f"{data} is Clean")