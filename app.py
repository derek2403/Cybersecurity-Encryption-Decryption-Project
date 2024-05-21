from flask import Flask, redirect, render_template, request, jsonify, url_for
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import secrets
import os
import smtplib
from email.mime.text import MIMEText
import threading
import time
import sys

app = Flask(__name__)

SENSITIVE_PATTERNS = [
    r'\b\d{16}\b',  # Credit card number
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email address
    r'\b\d{1,2}/\d{1,2}/\d{4}\b',  # Date (MM/DD/YYYY or similar)
    r'\b[A-Z]{2}\d{7}\b',  # Passport number
    r'\b01\d{8,9}\b',  # Phone number
    r'\b\+\d{1,3}\d{9,}\b',  # International phone number
    r'\b\d{12}\b',  # Identification number (12 digits)
    r'\b\d{3}-\d{2}-\d{4}\b',  # Social Security Number (SSN)
    r'\b[A-Z]{1,3}\d{1,4}[A-Z]?\b',  # Car plate number without dashes (e.g., ABC1234D)
    r'\b\d{9,12}\b',  # Bank account number (9-12 digits)
    r'\b\d{2}/\d{2}\b',  # Credit card expiration date (MM/YY)
    r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',  # Cryptocurrency wallet address (Bitcoin example)
    r'\b[A-Z]{2}\d{8}\b',  # Insurance policy number (simple pattern)
    r'\b\d{8}\b',  # Driver's license number (simple pattern)
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address (IPv4)
    r'\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b',  # MAC address
    r'\b[A-HJ-NPR-Z0-9]{17}\b',  # Vehicle Identification Number (VIN)
    r'\b\d{9}\b',  # Bank routing number (simple pattern)
    r'\b\d{2}-\d{7}\b',  # Tax Identification Number (TIN)
    r'\b\d{3}\b|\b\d{4}\b',  # CVV/CVC code (3-4 digits)
]

financial_data = {
    'accounts': [
        {"account_number": "111111111", "balance": 400000.00},
        {"account_number": "826749203", "balance": 7345.28},
        {"account_number": "173940284", "balance": 2489.47},
        {"account_number": "509384756", "balance": 6017.85},
        {"account_number": "384092175", "balance": 9873.12},
        {"account_number": "605273849", "balance": 3654.09},
        {"account_number": "482093571", "balance": 4728.33},
        {"account_number": "193847560", "balance": 8231.77},
        {"account_number": "920384756", "balance": 2567.43},
        {"account_number": "283746509", "balance": 6792.20},
        {"account_number": "394857102", "balance": 7543.89},
        {"account_number": "571039284", "balance": 4259.66},
        {"account_number": "684209375", "balance": 9012.54},
        {"account_number": "472839105", "balance": 3127.58},
        {"account_number": "503948726", "balance": 6894.15}
    ]
}


patients_db = []

AES_KEY = secrets.token_bytes(32)


def encrypt_data(data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_data_with_iv = iv + encrypted_data
    encrypted_data_b64 = b64encode(encrypted_data_with_iv)
    return encrypted_data_b64.decode('utf-8')

def decrypt_data(encrypted_data_b64):
    encrypted_data_with_iv = b64decode(encrypted_data_b64)
    iv = encrypted_data_with_iv[:AES.block_size]
    encrypted_data = encrypted_data_with_iv[AES.block_size:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/demo1')
def demo1():
    return render_template('demo1.html')

@app.route('/detect', methods=['POST'])
def detect_leak():
    data = request.form['data']
    encrypted_data = encrypt_data(data)
    result = detect_data_leak(data)
    compliance_check = check_compliance(data)
    incident_response = handle_incident_response(result, data)
    response = {
        'result': result,
        'encrypted_data': encrypted_data,
        'compliance_check': compliance_check,
        'incident_response': incident_response
    }
    return jsonify(response)

def detect_data_leak(data):
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, data):
            return "Potential data leak detected!"
    return "No data leak found."

def check_compliance(data):
    compliance_issues = []
    if re.search(r'\bGDPR\s*(?:Article)?\s*\d+\b', data, re.IGNORECASE):
        compliance_issues.append("Potential GDPR violation detected.")
    if re.search(r'\bHIPAA\b', data, re.IGNORECASE):
        compliance_issues.append("Potential HIPAA violation detected.")
    if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', data):
        compliance_issues.append("Potential PCI DSS violation detected.")
    if re.search(r'\bCCPA\b', data, re.IGNORECASE):
        compliance_issues.append("Potential CCPA violation detected.")
    return compliance_issues if compliance_issues else "No compliance issues found."

INCIDENT_LOG_FILE = 'incident_log.txt'
def handle_incident_response(result, data):
    notifications = []
    if "Potential data leak detected!" in result:
        log_file_path = os.path.join(os.getcwd(), INCIDENT_LOG_FILE)
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"Potential data leak detected:\n{data}\n\n")
        notifications.append("Incident report logged in the text file.")
    return notifications

@app.route('/decrypt_data', methods=['POST'])
def decrypt():
    encrypted_data = request.form['encrypted_data']
    decrypted_data = decrypt_data(encrypted_data)
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    data = request.form['message']
    encrypted_data = encrypt_data(data)
    return jsonify({'encrypted_data': encrypted_data})

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    encrypted_data = request.form['encrypted_data']
    decrypted_data = decrypt_data(encrypted_data)
    return jsonify({'decrypted_data': decrypted_data})

@app.route('/demo2')
def demo2():
    return render_template('demo2.html')

@app.route('/accounts')
def get_accounts():
    return jsonify(financial_data['accounts'])

@app.route('/demoPage')
def demoPage():
    return render_template('demoPage.html')

@app.route('/account/<account_number>')
def get_account(account_number):
    for account in financial_data['accounts']:
        if account['account_number'] == account_number:
            masked_account_number = account_number[0] + '*' * (len(account_number) - 2) + account_number[-1]
            formatted_balance = "${:,.2f}".format(account['balance'])
            return render_template('account_details.html', account_number=masked_account_number, balance=formatted_balance)
    return "Account not found"


@app.route('/breach')
def simulate_breach():
    return jsonify(financial_data)

@app.route('/login', methods=['POST'])
def login():
    account_number = request.form.get('account_number')  # Get account number from form data
    if account_number is None:
        return "Invalid account number", 400  # Return an error response if account_number is not provided
    return redirect(url_for('get_account', account_number=account_number))

@app.route('/demo3')
def demo3():
    return render_template('demo3.html')

@app.route('/register_patient', methods=['POST'])
def register_patient():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    medical_info = request.form['medical_info']

    encrypted_email = encrypt_data(email)
    encrypted_phone = encrypt_data(phone)
    encrypted_medical_info = encrypt_data(medical_info)

    patient = {
        'name': name,
        'email': encrypted_email,
        'phone': encrypted_phone,
        'medical_info': encrypted_medical_info
    }
    patients_db.append(patient)

    response = {
        'success': True,
        'encrypted_data': {
            'email': encrypted_email,
            'phone': encrypted_phone,
            'medical_info': encrypted_medical_info
        }
    }
    return jsonify(response)

@app.route('/patients')
def get_patients():
    decrypted_patients = []
    for patient in patients_db:
        decrypted_patients.append({
            'name': patient['name'],
            'email': decrypt_data(patient['email']),
            'phone': decrypt_data(patient['phone']),
            'medical_info': decrypt_data(patient['medical_info'])
        })
    return jsonify(decrypted_patients)

if __name__ == '__main__':
    app.run(debug=True)
