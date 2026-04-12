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

def normalize_df(df: pd.DataFrame, file_name: str) -> pd.DataFrame:
    """Normalize column names based on known dataset formats."""
    # Mapping for known files
    # 1. cve.csv
    if "cvss" in df.columns and "summary" in df.columns:
        print(f"[*] Normalizing columns for {file_name} (cve.csv format)")
        df = df.rename(columns={"cvss": "cvss_score", "summary": "description"})
    
    # 2. nvd_vulnerabilities_with_os.csv
    elif "CVSS Score" in df.columns and "Description" in df.columns:
        print(f"[*] Normalizing columns for {file_name} (nvd format)")
        df = df.rename(columns={"CVSS Score": "cvss_score", "Description": "description"})
        
    # Check if we have what we need
    if 'description' not in df.columns or 'cvss_score' not in df.columns:
        print(f"[!] Warning: {file_name} missing required columns. Skipping.")
        return pd.DataFrame()
        
    return df[['description', 'cvss_score']]

def train(data_paths: list[str]):
    all_dfs = []
    
    for path in data_paths:
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            continue
            
        print(f"[*] Loading: {path}")
        try:
            if path.endswith('.csv'):
                df = pd.read_csv(path)
            elif path.endswith('.json'):
                df = pd.read_json(path)
            else:
                print(f"[!] Unsupported format: {path}")
                continue
                
            norm_df = normalize_df(df, os.path.basename(path))
            if not norm_df.empty:
                all_dfs.append(norm_df)
        except Exception as e:
            print(f"[!] Error loading {path}: {e}")

    if not all_dfs:
        print("[!] No valid data loaded. Training aborted.")
        return

    # Merge all datasets
    df = pd.concat(all_dfs, ignore_index=True)
    
    # Drop missing values
    df = df.dropna(subset=['description', 'cvss_score'])
    
    # Ensure cvss_score is numeric
    df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
    df = df.dropna(subset=['cvss_score'])
    
    print(f"[+] Combined dataset size: {len(df)} samples")

    # Build Pipeline
    # Using TF-IDF vectorizer + Ridge Regression for a fast, efficient model
    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=5000,
        ngram_range=(1, 2)
    )
    model = Ridge(alpha=1.0)

    # Train
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
    parser.add_argument("--data", nargs="+", help="Path to training CSV/JSON files")
    parser.add_argument("--dir", help="Directory containing dataset files")
    args = parser.parse_args()
    
    paths = []
    if args.data:
        paths.extend(args.data)
    if args.dir:
        for f in os.listdir(args.dir):
            if f.endswith(('.csv', '.json')):
                paths.append(os.path.join(args.dir, f))
    
    if not paths:
        print("[!] No data files provided. Use --data or --dir")
    else:
        train(paths)
