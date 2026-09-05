# 🛡️ Phishing Email Detection Model

A machine learning-based web application that detects phishing emails using Python, Scikit-learn, TF-IDF, Logistic Regression, and Flask.

The system analyzes email content, URLs, and threat indicators to calculate an overall phishing risk score.

## 🚀 Features

- 📧 Email phishing detection
- 🤖 Machine Learning classification
- 🔗 URL security analysis
- 🧠 Threat indicator analysis
- ⚠️ Risk score calculation
- 📊 Security analysis dashboard
- 📄 Security report generation
- 💾 Downloadable security reports
- 🌐 Flask-based web interface

## 🛠️ Technologies Used

- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- TF-IDF
- Logistic Regression
- HTML
- CSS
- JavaScript

## 📂 Project Structure

```text
Phishing Email Detection Model/
│
├── app.py
├── train_model.py
├── predict_email.py
├── url_analyzer.py
├── threat_analyzer.py
├── requirements.txt
├── README.md
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
│   └── js/
│       └── app.js
│
├── templates/
│   └── index.html
│
└── .gitignore