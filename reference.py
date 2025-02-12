import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, 
                             confusion_matrix, roc_curve, auc)
from sklearn.ensemble import (RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier, 
                               ExtraTreesClassifier, HistGradientBoostingClassifier)
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from lightgbm.sklearn import LGBMClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.tree import DecisionTreeClassifier
from catboost import CatBoostClassifier
from sklearn.linear_model import BayesianRidge
import re
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS as stop_words
from urllib.parse import urlparse
import email
from email import policy
import dns.resolver
from bs4 import BeautifulSoup

# Additional Phishing Detection Classes
class EnhancedPhishingDetector:
    def __init__(self):
        self.tfidf = TfidfVectorizer(stop_words='english', max_features=5000)
        self.model = RandomForestClassifier(random_state=42)
        self.label_encoder = LabelEncoder()

    def extract_email_features(self, email_text):
        features = {}
        try:
            msg = email.message_from_string(email_text, policy=policy.default)
        except:
            msg = None

        features['has_subject'] = 1 if msg and msg['subject'] else 0
        features['reply_to_mismatch'] = 1 if msg and msg['from'] != msg['reply-to'] else 0
        features['contains_urgent_words'] = 1 if any(word in email_text.lower() 
            for word in ['urgent', 'immediate', 'action required', 'account suspended']) else 0
        features['contains_currency_symbols'] = 1 if any(symbol in email_text 
            for symbol in ['$', '€', '£', '¥']) else 0

        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', 
                          email_text)
        features['url_count'] = len(urls)
        features['suspicious_tld'] = 0
        features['mismatched_href'] = 0

        if urls:
            try:
                soup = BeautifulSoup(email_text, 'html.parser')
                links = soup.find_all('a')

                for link in links:
                    if link.get('href') and link.text:
                        if link.get('href') not in link.text:
                            features['mismatched_href'] = 1

                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
                for url in urls:
                    if any(tld in url.lower() for tld in suspicious_tlds):
                        features['suspicious_tld'] = 1
            except:
                pass

        return features

    def create_feature_matrix(self, emails):
        text_features = self.tfidf.transform(emails)
        additional_features = [list(self.extract_email_features(email).values()) for email in emails]
        additional_features_matrix = np.array(additional_features)
        return np.hstack((text_features.toarray(), additional_features_matrix))

    def fit(self, X_train, y_train):
        y_train_encoded = self.label_encoder.fit_transform(y_train)
        X_train_features = self.create_feature_matrix(X_train)
        self.model.fit(X_train_features, y_train_encoded)

    def predict_proba(self, X):
        X_features = self.create_feature_matrix(X)
        return self.model.predict_proba(X_features)

class EmailSecuritySystem:
    def __init__(self):
        self.phishing_detector = EnhancedPhishingDetector()
        self.spf_checker = SPFChecker()
        self.dkim_checker = DKIMChecker()

    def check_email(self, email_text):
        risk_score = 0
        risks = []

        # ML-based phishing detection
        phishing_prob = self.phishing_detector.predict_proba([email_text])[0][1]
        if phishing_prob > 0.7:
            risk_score += 0.4
            risks.append("High phishing probability detected")

        # Check authentication
        try:
            msg = email.message_from_string(email_text, policy=policy.default)
            if msg['from']:
                domain = msg['from'].split('@')[1]

                # SPF Check
                if not self.spf_checker.verify_spf(domain):
                    risk_score += 0.3
                    risks.append("SPF verification failed")

                # DKIM Check
                if not self.dkim_checker.verify_dkim(msg):
                    risk_score += 0.3
                    risks.append("DKIM verification failed")
        except:
            risk_score += 0.2
            risks.append("Unable to verify email authentication")

        return {
            'risk_score': min(risk_score, 1.0),
            'risks': risks,
            'action': 'block' if risk_score > 0.7 else 'flag' if risk_score > 0.4 else 'allow'
        }

class SPFChecker:
    def verify_spf(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            spf_records = resolver.resolve(domain, 'TXT')
            return any('v=spf1' in str(record) for record in spf_records)
        except:
            return False

class DKIMChecker:
    def verify_dkim(self, email_message):
        return 'DKIM-Signature' in email_message.keys()

# Integration into Randomize2 Workflow
def clean_text(text):
    text = re.sub(r'\W', ' ', text)
    text = text.lower()
    text = text.split()
    text = [word for word in text if word not in stop_words]
    return ' '.join(text)

data = pd.read_csv("C:\\Users\\sobha\\OneDrive\\Desktop\\CODING\\PE1\\updated_file.csv")
df = pd.read_csv("C:\\Users\\sobha\\OneDrive\\Desktop\\CODING\\PE1\\Phishing_Email.csv")

data = data.dropna(subset=['Email Text'])
df = df.dropna(subset=['Email Text'])

data['Cleaned Email'] = data['Email Text'].apply(clean_text)
df['Cleaned Email'] = df['Email Text'].apply(clean_text)

data1 = pd.concat([data, df], ignore_index=True)

X_train, X_test, y_train, y_test = df['Cleaned Email'], data['Cleaned Email'], df['Email Type'], data['Email Type']

# Train Enhanced Phishing Detector
enhanced_detector = EnhancedPhishingDetector()
enhanced_detector.tfidf.fit(X_train)
enhanced_detector.fit(X_train, y_train)

# Evaluate Models with Phishing Features
models = {
    'Random Forest': RandomForestClassifier(random_state=42),
    'Extra Trees': ExtraTreesClassifier(random_state=42),
    'AdaBoost': AdaBoostClassifier(n_estimators=100, random_state=42),
    'Gradient Boosting': GradientBoostingClassifier(random_state=42),
    'Logistic Regression': LogisticRegression(random_state=42)
}

results = []
for name, model in models.items():
    print(f"Training {name}...")
    try:
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(stop_words='english', max_features=5000)),
            ('model', model)
        ])
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        accuracy = round(accuracy_score(y_test, y_pred) * 100, 2)
        precision = round(precision_score(y_test, y_pred, average='weighted') * 100, 2)
        recall = round(recall_score(y_test, y_pred, average='weighted') * 100, 2)
        f1 = round(f1_score(y_test, y_pred, average='weighted') * 100, 2)
        results.append({'Model': name, 'Accuracy': accuracy, 'Precision': precision, 'Recall': recall, 'F1 Score': f1})
    except Exception as e:
        print(f"Error training {name}: {e}")

results_df = pd.DataFrame(results)
print(results_df.sort_values(by='Accuracy', ascending=False))
