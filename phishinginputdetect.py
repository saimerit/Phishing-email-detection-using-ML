import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import re
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS as stop_words

def clean_text(text):
    """Clean and preprocess the email text"""
    text = str(text)
    # Keep URLs for feature extraction
    text_with_urls = text.lower()
    # Clean text for TF-IDF
    text = re.sub(r'\W', ' ', text) 
    text = text.lower() 
    text = text.split()  
    text = [word for word in text if word not in stop_words] 
    return ' '.join(text), text_with_urls

def get_phishing_score(text):
    """Calculate phishing score based on multiple indicators"""
    score = 0
    text_lower = text.lower()
    
    # High-risk keywords and their weights
    urgent_words = {
        'urgent': 0.4,
        'immediate': 0.4,
        'suspended': 0.4,
        'verify': 0.4,
        'security': 0.3,
        'account': 0.3,
        'limited': 0.3,
        'unusual': 0.3,
        'click': 0.4,
        'secure': 0.2,
        'permanently': 0.3,
        'detected': 0.3,
        'validate': 0.3,
        'confirm': 0.3,
        'restricted': 0.3,
        'unauthorized': 0.3,
        'suspicious': 0.3,
        'login': 0.3,
        'expires': 0.3,
        'blocked': 0.3
    }
    
    # Check for urgent keywords
    for word, weight in urgent_words.items():
        if word in text_lower:
            score += weight
    
    # Check for URLs
    if 'http' in text_lower or 'www' in text_lower:
        score += 0.5
    
    # Check for exclamation marks
    score += min(text.count('!') * 0.1, 0.3)
    
    # Check for urgency patterns
    if '24 hours' in text_lower or 'immediately' in text_lower:
        score += 0.4
    
    # Check for threatening language
    if any(phrase in text_lower for phrase in ['will be suspended', 'will be blocked', 'will be closed']):
        score += 0.4
    
    # Cap the score at 1.0
    return min(score, 1.0)

def train_model(X_train, y_train):
    """Train the model with phishing-focused parameters"""
    tfidf = TfidfVectorizer(
        stop_words='english',
        max_features=10000,
        ngram_range=(1, 3),  # Include trigrams
        min_df=2
    )
    
    X_train_tfidf = tfidf.fit_transform(X_train)
    
    class_weight = {
        'Phishing Email': 3,
        'Safe Email': 1
    }
    
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight=class_weight,
        max_depth=20,
        min_samples_split=2,
        random_state=42
    )
    
    model.fit(X_train_tfidf, y_train)
    return tfidf, model

def classify_email(email_text, tfidf_vectorizer, trained_model):
    """Classify email with enhanced confidence calculation"""
    # Clean the input email text
    cleaned_email, text_with_urls = clean_text(email_text)
    
    # Get base prediction
    email_tfidf = tfidf_vectorizer.transform([cleaned_email])
    prediction = trained_model.predict(email_tfidf)[0]
    prediction_prob = trained_model.predict_proba(email_tfidf)[0]
    
    # Calculate phishing score
    phishing_score = get_phishing_score(email_text)
    
    # Adjust confidence based on phishing score
    if phishing_score > 0.3:  # If significant phishing indicators are present
        # Increase confidence for phishing prediction
        if prediction == 'Phishing Email':
            prediction_prob[1] = max(prediction_prob[1], phishing_score)
        else:
            # If model predicted safe but phishing score is high, adjust prediction
            if phishing_score > 0.5:
                prediction = 'Phishing Email'
                prediction_prob[1] = phishing_score
                prediction_prob[0] = 1 - phishing_score
    
    return prediction, prediction_prob, phishing_score

# Load and prepare the data
print("Loading data...")
data = pd.read_csv("updated_file.csv")
df = pd.read_csv("Phishing_Email.csv")

# Clean the data
data = data.dropna(subset=['Email Text'])
df = df.dropna(subset=['Email Text'])

# Print unique values in Email Type column
print("\nUnique values in Email Type column:", df['Email Type'].unique())

data['Cleaned Email'] = [clean_text(text)[0] for text in data['Email Text']]
df['Cleaned Email'] = [clean_text(text)[0] for text in df['Email Text']]

# Prepare training data
X_train = df['Cleaned Email']
y_train = df['Email Type']

# Train the model
print("Training the model...")
tfidf_vectorizer, trained_model = train_model(X_train, y_train)
print("Model training completed!")

def main():
    while True:
        print("\n=== Email Phishing Classifier ===")
        print("Enter 'q' to quit")
        email_text = input("\nPlease enter the email text to classify: ")
        
        if email_text.lower() == 'q':
            print("Goodbye!")
            break
        
        if not email_text.strip():
            print("Please enter some text to classify.")
            continue
        
        # Classify the email
        prediction, prediction_prob, phishing_score = classify_email(email_text, tfidf_vectorizer, trained_model)
        
        # Print results
        print("\n=== Classification Results ===")
        if prediction == 'Safe Email':
            result = "SAFE"
            confidence = (1 - phishing_score) * 100
        else:
            result = "PHISHING"
            confidence = max(prediction_prob[1], phishing_score) * 100
            
        print(f"Classification: {result}")
        print(f"Confidence: {confidence:.2f}%")
        
        # Show risk indicators for phishing emails
        if result == "PHISHING":
            print("\nRisk Indicators Found:")
            if 'urgent' in email_text.lower() or 'immediate' in email_text.lower():
                print("- Urgent language detected")
            if 'http' in email_text.lower() or 'www' in email_text.lower():
                print("- Suspicious URL detected")
            if '24 hours' in email_text.lower():
                print("- Time pressure tactics detected")
            if 'suspend' in email_text.lower() or 'block' in email_text.lower():
                print("- Threatening language detected")
            
            if confidence > 80:
                print("\n\033[91mHIGH RISK: This email shows strong characteristics of a phishing attempt!\033[0m")
            elif confidence > 60:
                print("\n\033[93mMEDIUM RISK: This email shows moderate characteristics of a phishing attempt.\033[0m")

if __name__ == "__main__":
    main()