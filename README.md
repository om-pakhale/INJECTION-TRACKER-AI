PROJECT 4 

# 🛡️ Injection Tracker

A machine learning-powered web application built with **Streamlit** that analyzes URLs and strings to detect potential injection attacks (SQL Injection, XSS, etc.).

## 🚀 Features
* **Intelligent URL Parsing:** Automatically extracts paths and queries from full URLs.
* **URL Decoding:** Handles percent-encoded characters and plus signs to reveal hidden payloads.
* **Probability-Based Detection:** Uses a trained Machine Learning model to provide a confidence score for its predictions.
* **Real-time Analysis:** Get instant feedback on whether a string is "Clean" or "Malicious."

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/injection-tracker.git](https://github.com/yourusername/injection-tracker.git)
    cd injection-tracker
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Required Files:**
    Ensure the following pre-trained files are in the root directory:
    * `full_injection_model.pkl` (The Scikit-Learn model)
    * `full_vectorizer.pkl` (The TF-IDF or Count Vectorizer)

## 🖥️ Usage

Run the application using Streamlit:

```bash
streamlit https://injection-tracker-ai-run.streamlit.app/
