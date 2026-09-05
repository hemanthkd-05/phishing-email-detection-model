import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

import matplotlib.pyplot as plt
import seaborn as sns


# ==============================
# 1. Load Dataset
# ==============================

DATASET_PATH = "dataset/emails.csv"

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")
print("Total emails:", len(df))


# ==============================
# 2. Clean Dataset
# ==============================

df = df.dropna(subset=["text", "label"])

df["text"] = df["text"].astype(str)
df["label"] = df["label"].str.lower().str.strip()


# ==============================
# 3. Convert Labels
# ==============================

df["label"] = df["label"].map({
    "safe": 0,
    "phishing": 1
})

df = df.dropna(subset=["label"])

X = df["text"]
y = df["label"]


# ==============================
# 4. Split Dataset
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# ==============================
# 5. TF-IDF Feature Extraction
# ==============================

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    max_features=5000,
    ngram_range=(1, 2)
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)


# ==============================
# 6. Train Model
# ==============================

model = LogisticRegression(
    max_iter=1000
)

model.fit(X_train_tfidf, y_train)


# ==============================
# 7. Make Predictions
# ==============================

y_pred = model.predict(X_test_tfidf)


# ==============================
# 8. Accuracy
# ==============================

accuracy = accuracy_score(y_test, y_pred)

print("\n================================")
print("PHISHING EMAIL DETECTION MODEL")
print("================================")

print(f"\nAccuracy: {accuracy * 100:.2f}%")


# ==============================
# 9. Classification Report
# ==============================

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Safe", "Phishing"]
    )
)


# ==============================
# 10. Confusion Matrix
# ==============================

cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix:")
print(cm)


# ==============================
# 11. Save Confusion Matrix
# ==============================

os.makedirs("results", exist_ok=True)

plt.figure(figsize=(6, 5))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    xticklabels=["Safe", "Phishing"],
    yticklabels=["Safe", "Phishing"]
)

plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Phishing Email Detection - Confusion Matrix")

plt.tight_layout()

plt.savefig(
    "results/confusion_matrix.png",
    dpi=300
)

plt.close()


# ==============================
# 12. Save Model
# ==============================

os.makedirs("models", exist_ok=True)

joblib.dump(
    model,
    "models/phishing_model.pkl"
)

joblib.dump(
    vectorizer,
    "models/tfidf_vectorizer.pkl"
)

print("\nModel saved successfully!")
print("Location: models/phishing_model.pkl")

print("\nConfusion matrix saved!")
print("Location: results/confusion_matrix.png")