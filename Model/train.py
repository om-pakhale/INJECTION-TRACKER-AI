import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import joblib 
from urllib.parse import urlparse , unquote
def expert_normalize(text):
    if not isinstance(text , str):
        return ""
    text = unquote(text).replace("+"," ")
    
    if text.startswith(('http://', 'https://')):
        parsed = urlparse(text)
        text = parsed.path + "?" + parsed.query
        
    return text.lower()


data =  pd.read_csv("SQLInjection_XSS_CommandInjection_MixDataset.1.0.0.csv")
df = pd.DataFrame(data)
df['label'] = df[['SQLInjection', 'XSS', 'CommandInjection']].max(axis=1)
df['Sentence']= df['Sentence'].apply(expert_normalize)
X_train , X_test , Y_train , Y_test = train_test_split(
    df['Sentence'], df['label'], random_state=42 , stratify=df['label']
)
vector = TfidfVectorizer(analyzer='char',ngram_range=(1, 3), max_features=20000,lowercase=True)
X_train_normal =  vector.fit_transform(X_train.values.astype('U'))
X_test_normal = vector.transform(X_test.values.astype('U'))

model = RandomForestClassifier(n_estimators=100,n_jobs=-1,class_weight='balanced',verbose=1)
print("Tranning Model...")
model.fit(X_train_normal,Y_train)

y_pred = model.predict(X_test_normal)
print("\n--- Model Evaluation ---")
print(classification_report(Y_test, y_pred))

joblib.dump(model, 'full_injection_model.pkl')
joblib.dump(vector, 'full_vectorizer.pkl')
print("Model updated")


