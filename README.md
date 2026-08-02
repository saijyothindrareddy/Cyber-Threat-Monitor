# Cyber Threat Monitoring System

A SOC-style dashboard that analyzes authentication logs and detects brute-force attacks.

## Features

• Log file upload and analysis  
• Brute-force attack detection  
• Threat severity classification  
• Security analytics dashboard  
• Attack statistics visualization  
• CSV export of alerts  

## Technologies Used

Python  
Flask  
Chart.js  
HTML / CSS / Bootstrap  

## Project Structure

cyber-threat-monitor
│
├── app.py
├── log_parser.py
├── threat_detector.py
├── requirements.txt
│
├── logs
│   └── sample_logs.txt
│
├── templates
│   ├── dashboard.html
│   ├── logs.html
│   ├── upload.html
│   ├── network.html
│   └── system.html

## How It Works

1. Upload authentication logs.
2. The system parses the logs.
3. If an IP performs multiple failed logins, it is detected as a brute-force attack.
4. The dashboard visualizes alerts and attack statistics.

## Run the Project

Install dependencies

pip install -r requirements.txt

Run the application

python app.py

Open browser

http://127.0.0.1:5000

## Author

Sai Jyothindra Reddy