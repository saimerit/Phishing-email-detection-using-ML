import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import re
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS as stop_words

def clean_text(text):
    """Clean and preprocess the email text"""
    text = re.sub(r'\W', ' ', text) 
    text = text.lower() 
    text = text.split()  
    text = [word for word in text if word not in stop_words] 
    return ' '.join(text)

def train_model(X_train, y_train):
    """Train the model with the best performing classifier"""
    # Initialize TF-IDF vectorizer and model
    tfidf = TfidfVectorizer(stop_words='english', max_features=5000)
    model = RandomForestClassifier(random_state=42)
    
    # Fit the TF-IDF vectorizer and transform the training data
    X_train_tfidf = tfidf.fit_transform(X_train)
    
    # Train the model
    model.fit(X_train_tfidf, y_train)
    
    return tfidf, model

def classify_email(email_text, tfidf_vectorizer, trained_model):
    """Classify a single email text as phishing or safe"""
    # Clean the input email text
    cleaned_email = clean_text(email_text)
    
    # Transform the cleaned email text using the fitted TF-IDF vectorizer
    email_tfidf = tfidf_vectorizer.transform([cleaned_email])
    
    # Make prediction
    prediction = trained_model.predict(email_tfidf)[0]
    prediction_prob = trained_model.predict_proba(email_tfidf)[0]
    
    return prediction, prediction_prob

# Load and prepare the data
data = pd.read_csv("C:\\Users\\sobha\\OneDrive\\Desktop\\CODING\\PE1\\updated_file.csv")
df = pd.read_csv("C:\\Users\\sobha\\Downloads\\Phishing_Email.csv\\Phishing_Email.csv")

# Clean the data
data = data.dropna(subset=['Email Text'])
df = df.dropna(subset=['Email Text'])

data['Cleaned Email'] = data['Email Text'].apply(clean_text)
df['Cleaned Email'] = df['Email Text'].apply(clean_text)

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
        prediction, prediction_prob = classify_email(email_text, tfidf_vectorizer, trained_model)
        
        # Print results
        print("\n=== Classification Results ===")
        if prediction == 0:
            result = "SAFE"
            confidence = prediction_prob[0] * 100
        else:
            result = "PHISHING"
            confidence = prediction_prob[1] * 100
            
        print(f"Classification: {result}")
        print(f"Confidence: {confidence:.2f}%")
        
        # Additional warning for high-risk emails
        if result == "PHISHING" and confidence > 80:
            print("\nWARNING: This email shows strong characteristics of a phishing attempt!")
        elif result == "PHISHING" and confidence > 60:
            print("\nCAUTION: This email shows moderate characteristics of a phishing attempt.")

if __name__ == "__main__":
    main()