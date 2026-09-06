# Phishing Email Detection Model

A machine learning-based cybersecurity application that detects phishing emails using Natural Language Processing (NLP), TF-IDF vectorization, Logistic Regression, URL analysis, and threat indicator analysis.

The project provides a professional SOC-style dashboard for analyzing email messages and generating a security risk report.

---

# Project Description

Phishing is a common cybersecurity attack where attackers send fake emails to trick users into revealing sensitive information such as passwords, banking details, login credentials, and personal information.

This project detects potentially malicious phishing emails by analyzing the content of an email and identifying suspicious patterns.

The system combines machine learning with security-based rule analysis to determine whether an email is **PHISHING** or **SAFE**.

The system also analyzes URLs and identifies different threat indicators to calculate an overall security risk score.

---

# Features

## Machine Learning Detection

- Email text classification
- TF-IDF text vectorization
- Logistic Regression classification
- Phishing probability calculation
- Safe probability calculation
- Phishing/Safe prediction

## URL Security Analysis

- URL extraction
- IP address URL detection
- HTTP URL detection
- HTTPS URL detection
- Suspicious URL keyword detection
- Long URL detection
- Shortened URL detection
- URL risk score calculation

## Threat Analysis

The system detects:

- Urgency indicators
- Credential-related indicators
- Financial indicators
- Threat indicators
- Reward indicators

## Security Risk Assessment

The system generates:

- Final security result
- Final risk score
- Risk level
- Machine learning analysis
- URL security analysis
- Threat analysis
- Risk indicators
- Security recommendations

## Web Dashboard

The Flask web application provides:

- Professional SOC-style dashboard
- Email scanner
- URL analysis
- Threat analytics
- Risk gauge
- Detection pipeline
- Security statistics
- Downloadable security report

---

# Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Programming language |
| Flask | Web application framework |
| Scikit-learn | Machine learning |
| TF-IDF | Text feature extraction |
| Logistic Regression | Email classification |
| Pandas | Dataset processing |
| NumPy | Numerical operations |
| Matplotlib | Visualization |
| Seaborn | Confusion matrix |
| HTML | Web interface |
| CSS | Dashboard design |
| JavaScript | Frontend functionality |
| Git | Version control |
| GitHub | Source code hosting |

---

# Project Structure

```text
Phishing Email Detection Model/
│
├── dataset/
│   └── emails.csv
│
├── models/
│   ├── phishing_model.pkl
│   └── tfidf_vectorizer.pkl
│
├── results/
│   └── confusion_matrix.png
│
├── static/
│   ├── css/
│   │   └── style.css
│   │
│   └── js/
│       └── app.js
│
├── templates/
│   └── index.html
│
├── venv/
│
├── app.py
├── train_model.py
├── predict_email.py
├── predict_email_backup.py
├── url_analyzer.py
├── threat_analyzer.py
├── requirements.txt
├── README.md
└── .gitignore
```

## How to Execute the Project

### Step 1: Activate Virtual Environment

Run:

.\venv\Scripts\Activate.ps1

### Step 2: Install Dependencies

Run:

python -m pip install -r requirements.txt

### Step 3: Train the Model

Run:

python train_model.py

### Step 4: Start the Flask Application

Run:

python app.py

The application will start at:

http://127.0.0.1:5000

### Step 5: Open the Web Application

Open a browser and visit:

http://127.0.0.1:5000

### Step 6: Analyze an Email

Enter an email message into the Email Scanner and click **Analyze Email**.

The system provides:

- Phishing/Safe classification
- Phishing probability
- URL security analysis
- Threat indicators
- Risk score
- Risk level
- Security recommendations
- Downloadable security report