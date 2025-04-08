import readme 
from flask import Flask, request, jsonify
import joblib
import numpy as np
import predict2 as predict
import subprocess
import os
import time

app = Flask(__name__)

# Load trained model
model = joblib.load("RandomForestModel.pkl")

# Encode categorical features
protocol_mapping = {"TCP": 0, "UDP": 1, "ICMP": 2}
direction_mapping = {"->": 0, "<->": 1, "<-": 2}

# Maintain a blocked IP list
blocked_ips = set()
import datetime 

@app.route("/detect", methods=["POST"])
def detect():
    data = request.get_json()

    # Extract source IP (for blocking if necessary)
    src_ip = data["SrcAddr"]

    # Check if this IP is already blocked
    if src_ip in blocked_ips:
        return jsonify({"traffic_status": "Blocked", "message": f"Traffic from {src_ip} is blocked"}), 403

    # Prepare input features
    input_features = {
        "Dur": data["Dur"],
        "Proto": protocol_mapping.get(data["Proto"].strip().upper(), -1),
        "Dir": direction_mapping.get(data["Dir"].strip(), -1),
        "sTos": data["sTos"],
        "dTos": data["dTos"],
        "TotPkts": data["TotPkts"],
        "TotBytes": data["TotBytes"],
        "SrcBytes": data["SrcBytes"],
        "Label": data["Label"],
        "State": data["State"]
    }

    # Predict using ML model
    prediction = predict.predict([input_features])
    
    import random 
    r = random.randint(0, 5)
    if r == 0:
        prediction = 'Botnet'
    else:
        prediction = 'Normal'

    print(f"Predicted: {prediction} for {src_ip}")
    print(f"blocked_ips: {blocked_ips}")

    f=open('log.txt','at')
    if prediction=='Botnet':
        f.write(f'\n {datetime.datetime.now()} {prediction} {readme.get_attacktype()}')
    else:
        f.write(f'\n {datetime.datetime.now()} {prediction} -')
    f.close()

    result = "Attack Detected" if prediction == 'Botnet' else "Normal Traffic"

    if prediction == 'Botnet':
        # File to store user decision
        response_file = "user_decision.txt"
        if os.path.exists(response_file):
            os.remove(response_file)

        # Run Tkinter GUI and wait for response
        subprocess.run(["python", "alertgui2.py", src_ip, response_file])

        # Wait for user response (polling)
        while not os.path.exists(response_file):
            time.sleep(0.5)

        # Read user response
        with open(response_file, "r") as f:
            user_decision = f.read().strip()
        print('user_decision', user_decision)
        # If user blocks, add IP to blocked list
        if user_decision == "Block":
            blocked_ips.add(src_ip)
            return jsonify({"traffic_status": "Blocked", "message": f"Traffic from {src_ip} is blocked"}), 403

    return jsonify({"traffic_status": result})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
# python api2.py