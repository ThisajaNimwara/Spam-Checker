from flask import Flask, render_template, request, jsonify
import pickle
import requests
import subprocess
import tempfile
import os
import re
import base64
import email.parser
import extract_msg
from io import BytesIO
import time  # Optional, in case of future polling

# Ensure Flask knows where templates and static live since this file is in `src/`
app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Load model (adjusted to correct path and resilient usage)
MODEL_PATHS_TO_TRY = [
    os.path.join(os.path.dirname(__file__), '..', 'Model', 'spam_model.pkl'),
    os.path.join(os.path.dirname(__file__), '..', 'models', 'spam_model.pkl'),
    os.path.join(os.path.dirname(__file__), 'spam_model.pkl'),
]

model = None
MODEL_PATHS_RESOLVED = []
MODEL_LOAD_ERROR = None
for candidate_path in MODEL_PATHS_TO_TRY:
    try:
        resolved_path = os.path.abspath(candidate_path)
        MODEL_PATHS_RESOLVED.append({
            'path': resolved_path,
            'exists': os.path.exists(resolved_path)
        })
        if MODEL_PATHS_RESOLVED[-1]['exists']:
            with open(resolved_path, 'rb') as f:
                model = pickle.load(f)
            break
    except Exception as e:
        MODEL_LOAD_ERROR = str(e)
        continue

# API keys (read from environment if available; features are optional)
SPAMCHECK_API_KEY = os.getenv("yl6zzElknAa1EXzh4dSToAfGapGPV6Cz")
VIRUSTOTAL_API_KEY = os.getenv("5587c0965cecffe91a095cb28a0aaf5a740624c2420684adc3d9f5ce851c9514")

# Helper function to get email body from EML message
def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(errors='ignore')
                break
            elif part.get_content_type() == 'text/html' and not body:
                body = part.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')
    return body

# Function for your ML model (supports sklearn Pipeline or raw estimators)
def get_model_prob(email_text):
    if model is None:
        return 0.0
    try:
        # If model is a sklearn Pipeline that can handle raw text
        if hasattr(model, 'predict_proba'):
            try:
                # First try with raw text (works if pipeline handles vectorization)
                proba = model.predict_proba([email_text])[0]
                return float(proba[1]) if len(proba) > 1 else float(proba)
            except Exception:
                pass
        # If we get here, attempt to handle models that expect numeric arrays
        # Fallback: return neutral probability
        return 0.5
    except Exception:
        return 0.0

# Function for Rspamd (Docker at localhost:11333)
def get_rspamd_prob(email_text):
    rspamd_url = "http://localhost:11333/check"
    try:
        response = requests.post(rspamd_url, data=email_text.encode())
        if response.status_code == 200:
            data = response.json()
            score = data.get('score', 0)
            return min(score / 15.0, 1.0)
    except:
        pass
    return 0.0

# Function for Apache SpamAssassin (local)
def get_spamassassin_prob(email_text):
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(
                f"From: test@example.com\nTo: user@example.com\nSubject: Pasted Email\n\n{email_text}"
            )
            temp_path = temp_file.name
        # Use spamc correctly without shell redirection token
        result = subprocess.run(['spamc', '-c', temp_path], capture_output=True, text=True)
        try:
            os.unlink(temp_path)
        except Exception:
            pass
        # spamc -c returns score and threshold like: "5.0/10.0"
        if result.returncode == 0 and '/' in result.stdout:
            score_part = result.stdout.strip().split('/')[0]
            score = float(score_part)
            return min(score / 10.0, 1.0)
        return 0.0
    except Exception:
        return 0.0

# Function for APILayer SpamCheck
def get_spamcheck_prob(email_text):
    if not SPAMCHECK_API_KEY:
        return 0.0
    url = "https://api.apilayer.com/spamchecker"
    headers = {"apikey": SPAMCHECK_API_KEY}
    try:
        response = requests.post(url, headers=headers, data=email_text.encode())
        if response.status_code == 200:
            data = response.json()
            score = data.get('score', 0)  # Adjust if API field differs
            return min(float(score) / 10.0, 1.0)
    except Exception:
        return 0.0
    return 0.0

# Function for VirusTotal URL scanning (checks for malicious URLs)
def get_virustotal_prob(email_text):
    if not VIRUSTOTAL_API_KEY:
        return 0.0
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    if not urls:
        return 0.0
    malicious_found = False
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        try:
            url_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(vt_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    malicious_found = True
                    break
            # Optional: If 404, could POST to scan, but skipping for speed
        except Exception:
            continue
    return 1.0 if malicious_found else 0.0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health():
    status = {
        'model': {
            'loaded': bool(model),
            'paths_checked': MODEL_PATHS_RESOLVED,
            'load_error': MODEL_LOAD_ERROR,
        },
        'spamcheck_api': {
            'configured': bool(SPAMCHECK_API_KEY),
            'reachable': False,
            'note': '',
        },
        'virustotal_api': {
            'configured': bool(VIRUSTOTAL_API_KEY),
            'reachable': False,
            'note': '',
        },
        'rspamd': {
            'reachable': False,
        },
        'spamassassin': {
            'available': False,
        }
    }

    # Check Rspamd reachability
    try:
        r = requests.post('http://localhost:11333/check', data=b'test')
        status['rspamd']['reachable'] = (r.status_code == 200)
    except Exception:
        status['rspamd']['reachable'] = False

    # Check spamc availability (SpamAssassin client)
    try:
        result = subprocess.run(['spamc', '-V'], capture_output=True, text=True)
        status['spamassassin']['available'] = (result.returncode == 0 or result.stdout != '')
    except Exception:
        status['spamassassin']['available'] = False

    # Check SpamCheck API if configured
    if SPAMCHECK_API_KEY:
        try:
            test_resp = requests.post('https://api.apilayer.com/spamchecker', headers={'apikey': SPAMCHECK_API_KEY}, data=b'test')
            status['spamcheck_api']['reachable'] = test_resp.status_code in (200, 400, 401)
            if test_resp.status_code == 401:
                status['spamcheck_api']['note'] = 'API key rejected (401)'
            elif test_resp.status_code == 400:
                status['spamcheck_api']['note'] = 'Endpoint reachable (400 Bad Request indicates connectivity)'
        except Exception as e:
            status['spamcheck_api']['reachable'] = False
            status['spamcheck_api']['note'] = 'Request failed'

    # Check VirusTotal if configured (use example.com id)
    if VIRUSTOTAL_API_KEY:
        try:
            url = 'http://example.com'
            url_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            vt_resp = requests.get(vt_url, headers=headers)
            status['virustotal_api']['reachable'] = vt_resp.status_code in (200, 404, 401)
            if vt_resp.status_code == 401:
                status['virustotal_api']['note'] = 'API key rejected (401)'
            elif vt_resp.status_code == 404:
                status['virustotal_api']['note'] = 'Endpoint reachable (404 means not previously analyzed)'
        except Exception:
            status['virustotal_api']['reachable'] = False

    return jsonify(status)

@app.route('/predict', methods=['POST'])
def predict():
    email_text = ""
    # Handle JSON for pasted text
    try:
        data = request.get_json()
        if data:
            email_text = data.get('email_text', '')
    except:
        pass
    
    # Handle form for text or file
    if not email_text:
        email_text = request.form.get('email_text', '')
    
    file = request.files.get('email_file')
    if file and file.filename:
        filename = file.filename.lower()
        if not (filename.endswith('.eml') or filename.endswith('.msg')):
            return jsonify({'error': 'Invalid file type. Only .eml and .msg supported.'}), 400
        file_content = file.read()
        subject = ""
        body = ""
        if filename.endswith('.eml'):
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(file_content)
            subject = msg['Subject'] or ""
            body = get_email_body(msg)
        elif filename.endswith('.msg'):
            # extract_msg works best with a file path; write to temp and load
            with tempfile.NamedTemporaryFile(delete=False) as temp_msg_file:
                temp_msg_file.write(file_content)
                temp_msg_path = temp_msg_file.name
            try:
                msg = extract_msg.Message(temp_msg_path)
                subject = msg.subject or ""
                body = (msg.body or "")
            finally:
                try:
                    os.unlink(temp_msg_path)
                except Exception:
                    pass
        email_text = subject + "\n\n" + body
    
    if not email_text:
        return jsonify({'error': 'No email text or file provided'}), 400
    
    # Compute probabilities; services are optional
    model_prob = get_model_prob(email_text)
    rspamd_prob = get_rspamd_prob(email_text)
    spamassassin_prob = get_spamassassin_prob(email_text)
    spamcheck_prob = get_spamcheck_prob(email_text)
    vt_prob = get_virustotal_prob(email_text)

    probs = [p for p in [model_prob, rspamd_prob, spamassassin_prob, spamcheck_prob, vt_prob] if isinstance(p, (int, float))]
    final_prob = (sum(probs) / len(probs)) if probs else 0.0
    label = "Phishing (Spam)" if final_prob > 0.5 else "Ham (Legit)"
    confidence = final_prob * 100
    
    return jsonify({
        'label': label,
        'confidence': f"{confidence:.1f}",
        'details': {
            'model': f"{model_prob * 100:.1f}",
            'rspamd': f"{rspamd_prob * 100:.1f}",
            'spamassassin': f"{spamassassin_prob * 100:.1f}",
            'spamcheck': f"{spamcheck_prob * 100:.1f}",
            'virustotal': f"{vt_prob * 100:.1f}"
        }
    })

if __name__ == '__main__':
    app.run(debug=True)