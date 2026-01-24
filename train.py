import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib 

data =  pd.read_csv("SQLInjection_XSS_CommandInjection_MixDataset.1.0.0.cv",)

df = pd.DataFrame(data)

vector = TfidfVectorizer(analyzer='char', ngram_range=(1, 3))
X = vector.fit(df['text'])
Y = df['label']

model = RandomForestClassifier()
model.fit(X,Y)

