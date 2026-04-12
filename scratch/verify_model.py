import sys
import os
sys.path.append(os.getcwd())
from core.ml_predictor import predictor

def test_prediction():
    print(f"[*] Testing ML Predictor...")
    print(f"[*] Model ready: {predictor.is_ready}")
    
    if not predictor.is_ready:
        print("[!] Model failed to load!")
        return

    test_desc = "Buffer overflow in the vector processor allows remote attackers to execute arbitrary code."
    score = predictor.predict(test_desc)
    print(f"[+] Prediction for '{test_desc}': {score}")
    
    if score is not None and 0.0 <= score <= 10.0:
        print("[+] Verification SUCCESSFUL")
    else:
        print("[!] Verification FAILED")

if __name__ == "__main__":
    test_prediction()
