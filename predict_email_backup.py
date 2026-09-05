import joblib


# Load trained model
model = joblib.load("models/phishing_model.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")


print("====================================")
print("     PHISHING EMAIL DETECTOR")
print("====================================")

email = input("\nPaste email text:\n")

# Convert email into TF-IDF features
email_features = vectorizer.transform([email])

# Prediction
prediction = model.predict(email_features)[0]

# Probability
probability = model.predict_proba(email_features)[0]

phishing_probability = probability[1] * 100
safe_probability = probability[0] * 100


print("\n====================================")

if prediction == 1:
    print("⚠️ RESULT: PHISHING")
    print(f"Phishing Confidence: {phishing_probability:.2f}%")
else:
    print("✅ RESULT: SAFE")
    print(f"Safe Confidence: {safe_probability:.2f}%")

print("====================================")