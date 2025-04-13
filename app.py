from flask import Flask, render_template, request, redirect, url_for, jsonify  # type: ignore
from detector.rule_factory import RuleFactory
from flask_cors import CORS  # type: ignore
import joblib
import torch
import numpy as np
import re
from urllib.parse import urlparse
from transformers import BertTokenizer, BertModel

app = Flask(__name__)
CORS(app)

# Load model & tokenizer
bert_model = joblib.load('bert_phishing_model.pkl')
tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
bert_extractor = BertModel.from_pretrained("bert-base-uncased")

def extract_bert_embeddings(text):
    tokens = tokenizer(text, padding=True, truncation=True, return_tensors="pt")
    with torch.no_grad():
        outputs = bert_extractor(**tokens)
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

def check_email(email):
    rules = ["suspicious_links", "sender_address"]
    results = {}

    # Rule-based analysis
    for rule_type in rules:
        rule = RuleFactory.get_rule(rule_type)
        results[rule_type] = rule.check(email)

    # BERT + URL features
    body = email.get('body', '')
    bert_embedding = extract_bert_embeddings(body).reshape(1, -1)
    url_features = np.array(extract_url_features(body)).reshape(1, -1)
    combined_input = np.hstack([bert_embedding, url_features])

    prediction = bert_model.predict(combined_input)[0]
    results['bert_prediction'] = 'phishing' if prediction == 1 else 'legitimate'
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'clear' in request.form:
            return redirect(url_for('index'))

        email = {
            'from': request.form['from'],
            'subject': request.form['subject'],
            'body': request.form['body']
        }
        results = check_email(email)
        return render_template('index.html', email=email, results=results)

    return render_template('index.html', email=None, results=None)

@app.route('/detect', methods=['POST'])
def detect_phishing():
    data = request.get_json()
    email_text = {
        'from': data.get('from'),
        'subject': data.get('subject'),
        'body': data.get('body')
    }
    results = check_email(email_text)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
