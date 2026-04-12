"""
Model Training Script for Vulnix CVSS Predictor
===============================================
Usage: python scripts/train_cvss.py --data my_dataset.csv
"""

import os
import argparse
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import Ridge
from sklearn.pipeline import Pipeline
import joblib

# Ensure the script can find config
import sys
sys.path.append(os.getcwd())
import config

def train(data_path: str):
    print(f"[*] Loading training data from: {data_path}")
    
    # Load data
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith('.json'):
        df = pd.read_json(data_path)
    else:
        print("[!] Unsupported file format. Use .csv or .json")
        return

    # Expecting columns: 'description' and 'cvss_score'
    if 'description' not in df.columns or 'cvss_score' not in df.columns:
        print("[!] Dataset must contain 'description' and 'cvss_score' columns.")
        return

    # Drop missing values
    df = df.dropna(subset=['description', 'cvss_score'])
    print(f"[*] Training on {len(df)} samples...")

    # Build Pipeline
    # Using TF-IDF vectorizer + Ridge Regression for a fast, efficient model
    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=5000,
        ngram_range=(1, 2)
    )
    model = Ridge(alpha=1.0)

    # Train (separately so we can save them as a dict)
    print("[*] Vectorizing text...")
    X = vectorizer.fit_transform(df['description'])
    y = df['cvss_score']

    print("[*] Fitting Ridge model...")
    model.fit(X, y)

    # Save
    out_path = config.CVSS_MODEL_PATH
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    joblib.dump({
        "model": model,
        "vectorizer": vectorizer
    }, out_path)
    
    print(f"[+] Model successfully saved to: {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Vulnix CVSS Predictor")
    parser.add_argument("--data", required=True, help="Path to training CSV/JSON")
    args = parser.parse_args()
    
    train(args.data)
