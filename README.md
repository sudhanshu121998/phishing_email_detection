# Phishing Email Detector

Phishing Email Detector is a web application and Chrome extension designed to help users detect phishing emails. The web application uses Flask to allow users to input email details and check for phishing indicators based on predefined rules. The Chrome extension allows users to check emails directly from their Gmail inbox.

## Features

- **Web Application**: Input email details and get a phishing detection report.
- **Chrome Extension**: Check phishing emails directly from your Gmail inbox with a simple click.
- **Rule-Based Detection**: Checks emails for suspicious links, sender addresses, and urgent language.

## Web Application

### Requirements

- Python
- Flask
- Flask-cors

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/pranjalsingh03/phising-email-detector.git
    cd phishing-email-detector
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the Flask application:
    ```bash
    python app.py
    ```

4. Open your browser and go to `http://127.0.0.1:5000/`.

### File Structure

- `app.py`: The main Flask application.
- `templates/index.html`: The HTML template for the web application.
- `static/styles.css`: The CSS file for styling the web application.
- `detector/rule_factory.py`: Contains the logic for the phishing detection rules.

### Usage

1. Open the web application in your browser.
2. Enter the email details (From, Subject, Body).
3. Click "Check Email" to get the phishing detection report.
4. To clear the report, click "Clear Report".

## Chrome Extension

### Installation

1. Open Chrome and go to `chrome://extensions/`.
2. Enable "Developer mode" using the toggle switch in the top right.
3. Click "Load unpacked" and select the `chrome_extension` directory from the repository.

### Usage

1. Open Gmail in Chrome.
2. Click the Phishing Email Detector icon in the Chrome toolbar

