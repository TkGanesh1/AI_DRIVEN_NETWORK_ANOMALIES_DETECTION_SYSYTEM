import sys
import requests
import time
import random
import numpy as np
import readme 
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QSplitter, QHBoxLayout

# Define the relevant feature names
features = ["Dur", "Proto", "Dir", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes"]
protocols = ["TCP", "UDP", "ICMP"]
directions = ["->", "<->", "<-"]

# Random IP address generator
def generate_ip():
    return f"192.168.100.{np.random.randint(1, 25)}"

# Generate random attack signatures
def generate_malicious_traffic():
    return {
        "Dur": np.random.uniform(5.0, 20.0),  # Longer duration for attacks
        "Proto": np.random.choice(protocols),
        "Dir": np.random.choice(directions),
        "TotPkts": np.random.randint(100, 500),  # Higher packet count
        "TotBytes": np.random.randint(5000, 20000),  # More bytes
        "SrcBytes": np.random.randint(2500, 10000),  # More aggressive data transfer
        "Label": "Anomaly",  # Attack label (anomaly)
        "State": 1,  # Assume '1' indicates abnormal behavior
        "sTos": np.random.randint(10, 20),  # Higher ToS values
        "dTos": np.random.randint(10, 20),
        "StartTime": "2023-01-01 00:00:00",
        "SrcAddr": generate_ip(),  # Random attacker IP
        "Sport": np.random.randint(1024, 65535),
        "DstAddr": generate_ip(),  # Random victim IP
        "Dport": np.random.choice([22, 80, 443, 3389])  # Common attack targets (SSH, HTTP, HTTPS, RDP)
    }

# Generate normal traffic
def generate_normal_traffic():
    return {
        "Dur": np.random.uniform(0.1, 5.0),  # Shorter session
        "Proto": np.random.choice(protocols),
        "Dir": np.random.choice(directions),
        "TotPkts": np.random.randint(1, 100),
        "TotBytes": np.random.randint(100, 5000),
        "SrcBytes": np.random.randint(50, 2500),
        "Label": "Normal",  # No anomaly (normal behavior)
        "State": 0,  # Normal behavior
        "sTos": np.random.randint(0, 10),
        "dTos": np.random.randint(0, 10),
        "StartTime": "2023-01-01 00:00:00",
        "SrcAddr": generate_ip(),
        "Sport": np.random.randint(1024, 65535),
        "DstAddr": generate_ip(),
        "Dport": np.random.randint(1024, 65535)
    }

# NetSim Thread (background worker for traffic generation)
class NetSimThread(QThread):
    update_signal = pyqtSignal(str)
    prediction_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True  # Flag to control the traffic generation

    def run(self):
        while self.running:
            # Generate either normal or malicious traffic
            if np.random.rand() < 0.3:
                traffic = generate_malicious_traffic()
                self.update_signal.emit(f"⚠️ Simulated ANOMALY Traffic: {traffic}")
            else:   
                traffic = generate_normal_traffic()
                self.update_signal.emit(f"✅ Simulated NORMAL Traffic: {traffic}")
            
            # Send traffic to Flask API for detection
            try:
                response = requests.post("http://127.0.0.1:5000/detect", json=traffic)
                prediction_data = response.json()
                traffic_status = prediction_data.get("traffic_status", "Unknown")


                if traffic_status=='Attack Detected':
                    traffic_status = 'Attack Detected:'+ readme.get_attacktype()

                if traffic_status=='Attack Detected':
                    self.prediction_signal.emit(f"Prediction: {traffic_status} {readme.get_attacktype()}")
                else:
                    self.prediction_signal.emit(f"Prediction: {traffic_status} ")
            except Exception as e:
                self.update_signal.emit(f"❌ Error sending traffic: {e}")
            
            time.sleep(1)  # Simulate real-time traffic flow
    
    def stop(self):
        self.running = False  # Flag to stop the loop
        self.quit()

# API Thread (background worker for managing API status)
class APIThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        # Simulate Flask API running
        while True:
            self.update_signal.emit("Flask API is running...")
            time.sleep(5)

    

    def stop(self):
        self.quit()

# GUI Application
class NIDSApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('NIDS: Network Intrusion Detection System')
        self.setGeometry(100, 100, 800, 400)

        # Create GUI Elements for NetSim (Left Panel)
        self.start_sim_button = QPushButton('Start NetSim', self)
        self.stop_sim_button = QPushButton('Stop NetSim', self)
        self.simulation_log = QTextEdit(self)
        self.simulation_log.setReadOnly(True)

        # Create GUI Elements for API (Right Panel)
        self.start_api_button = QPushButton('Start API', self)
        self.stop_api_button = QPushButton('Stop API', self)
        self.api_log = QTextEdit(self)
        self.api_log.setReadOnly(True)

        # Layout for Left and Right Panels using QSplitter
        left_panel_layout = QVBoxLayout()
        left_panel_layout.addWidget(QLabel("<h3>NetSim Controls</h3>", self))
        left_panel_layout.addWidget(self.start_sim_button)
        left_panel_layout.addWidget(self.stop_sim_button)
        left_panel_layout.addWidget(QLabel("NetSim Log", self))
        left_panel_layout.addWidget(self.simulation_log)

        right_panel_layout = QVBoxLayout()
        right_panel_layout.addWidget(QLabel("<h3>API Controls</h3>", self))
        right_panel_layout.addWidget(self.start_api_button)
        right_panel_layout.addWidget(self.stop_api_button)
        right_panel_layout.addWidget(QLabel("API Log", self))
        right_panel_layout.addWidget(self.api_log)

        splitter = QSplitter(Qt.Horizontal)
        left_panel = QWidget()
        left_panel.setLayout(left_panel_layout)
        right_panel = QWidget()
        right_panel.setLayout(right_panel_layout)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)

        # Main layout
        main_layout = QHBoxLayout()
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

        # Connect buttons to methods
        self.start_sim_button.clicked.connect(self.start_simulation)
        self.stop_sim_button.clicked.connect(self.stop_simulation)
        self.start_api_button.clicked.connect(self.start_api)
        self.stop_api_button.clicked.connect(self.stop_api)

        # Create background thread for NetSim simulation
        self.sim_thread = NetSimThread()
        self.sim_thread.update_signal.connect(self.update_sim_log)
        self.sim_thread.prediction_signal.connect(self.update_prediction)

        # Create background thread for API management
        self.api_thread = APIThread()
        self.api_thread.update_signal.connect(self.update_api_log)

    def start_simulation(self):
        self.simulation_log.append("Starting NetSim simulation...")
        self.sim_thread.start()

    def stop_simulation(self):
        self.sim_thread.stop()
        self.sim_thread.wait()
        self.simulation_log.append("NetSim simulation stopped.")

    def start_api(self):
        self.api_log.append("Starting Flask API...")
        self.api_thread.start()

    def stop_api(self):
        self.api_thread.stop()
        self.api_thread.wait()
        self.api_log.append("Flask API stopped.")

    def update_sim_log(self, message):
        self.simulation_log.append(message)

    def update_api_log(self, message):
        self.api_log.append(message)

    def update_prediction(self, prediction):
        self.api_log.append(f"Prediction: {prediction}")

def main():
    app = QApplication(sys.argv)
    nids_app = NIDSApp()
    nids_app.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
