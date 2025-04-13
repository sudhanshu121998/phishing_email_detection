import pandas as pd
import numpy as np
import re
import streamlit as st
import joblib
import torch
from transformers import BertTokenizer, BertModel
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from urllib.parse import urlparse
import requests

# Load BERT tokenizer and model
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
bert_model = BertModel.from_pretrained("bert-base-uncased")

def extract_bert_embeddings(text):
    tokens = tokenizer(text, padding=True, truncation=True, return_tensors="pt")
    with torch.no_grad():
        outputs = bert_model(**tokens)
    return outputs.last_hidden_state[:, 0, :].squeeze().numpy()

def extract_url_features(email_body):
    urls = re.findall(r'(https?://[^\s]+)', str(email_body))
    features = []
    
    for url in urls:
        parsed_url = urlparse(url)
        domain_length = len(parsed_url.netloc)
        path_length = len(parsed_url.path)
        protocol = 1 if parsed_url.scheme in ['http', 'https'] else 0
        features.append([domain_length, path_length, protocol])
        
    return np.mean(features, axis=0) if features else [0, 0, 0]

def train_model(data):
    # Clean dataset
    data = data[['email_body', 'label']].dropna()
    data['label'] = data['label'].map({'Safe Email': 0, 'Phishing Email': 1})
    
    data['bert_embeddings'] = data['email_body'].apply(extract_bert_embeddings)
    data['url_features'] = data['email_body'].apply(extract_url_features)
    
    X_bert = np.vstack(data['bert_embeddings'].values)
    X_url = np.vstack(data['url_features'].values)
    X = np.hstack([X_bert, X_url])
    y = data['label']
    
    model = LogisticRegression()
    model.fit(X, y)
    
    joblib.dump(model, 'bert_phishing_model.pkl')
    return model

def predict_phishing(model, email_body):
    bert_embedding = extract_bert_embeddings(email_body).reshape(1, -1)
    url_features = np.array(extract_url_features(email_body)).reshape(1, -1)
    X = np.hstack([bert_embedding, url_features])
    
    prediction = model.predict(X)
    return 'Phishing Email' if prediction[0] == 1 else 'Safe Email'

def main():
    st.title("BERT-Powered Phishing Detection System")
    
    try:
        model = joblib.load('bert_phishing_model.pkl')
        st.write("Model loaded successfully!")
    except:
        st.write("No trained model found. Please train the model first.")
    
    email_input = st.text_area("Enter the Email Body to Check:", height=200)
    
    if st.button("Check Phishing"):
        if email_input:
            result = predict_phishing(model, email_input)
            st.write(f"Prediction: {result}")
        else:
            st.write("Please enter an email body for analysis.")
    
    st.subheader("Train the Model (Optional)")
    uploaded_file = st.file_uploader("Choose a CSV file with email data", type="csv")
    
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        if 'email_body' in data.columns and 'label' in data.columns:
            st.write("Training the model with the uploaded data...")
            model = train_model(data)
            st.write("Model trained and saved successfully!")

if __name__ == '__main__':
    main()
