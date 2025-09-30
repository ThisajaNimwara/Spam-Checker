Spam/Ham Email Detector
A Flask-based web application to classify emails as Spam (Phishing) or Ham (Legit) using an ensemble of a custom ML model, Rspamd, Apache SpamAssassin, APILayer SpamCheck API, and VirusTotal API for malicious URL detection. Users can paste email text or upload .eml or .msg files via a modern, responsive UI.
Features

Input Options: Paste email text or upload .eml/.msg files.
Ensemble Detection: Combines scores from XGBoost, Rspamd, SpamAssassin, SpamCheck, and VirusTotal (URL scanning).
UI: Responsive design with Tailwind CSS, tabbed interface, loading spinner, and detailed score breakdown.
Output: Color-coded verdict (red for spam, green for ham) with confidence percentage and toggleable details.

Project Structure
Spam Checker/
├── Data/
│   └── mails_dataset.csv      # Dataset (optional)
├── Model/
│   └── spam_model.pkl         # Trained model (required to use ML)
├── src/
│   └── app.py                 # Flask app with API endpoints
├── static/
│   ├── css/
│   │   └── style.css          # Custom CSS
│   └── js/
│       └── script.js          # Frontend JavaScript
├── templates/
│   └── index.html             # HTML template
├── requirements.txt           # Python dependencies
└── README.md                  # This file

Prerequisites

Python 3.9–3.12
(Optional) Docker: For running Rspamd.
(Optional) Apache SpamAssassin: Installed locally with spamc in PATH.
(Optional) API Keys:
  - APILayer SpamCheck (get from apilayer.com).
  - VirusTotal (get from virustotal.com).

Trained Model: `Model/spam_model.pkl` (place here). If missing, the app still runs but the model score will be 0.

Setup (Windows PowerShell)

1) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

2) Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

3) Place the trained model (optional but recommended)
Copy your trained model file to: Model\spam_model.pkl

4) Configure optional API keys (only if you want external checks)
$env:SPAMCHECK_API_KEY = "your-apilayer-key"
$env:VIRUSTOTAL_API_KEY = "your-virustotal-key"

5) (Optional) Start Rspamd via Docker
docker run --rm -p 11333:11333 rspamd/rspamd

6) (Optional) Install SpamAssassin
- Windows users typically skip this; the app works without it.
- On Linux: sudo apt install spamassassin spamc && sa-update





Running the App

Start the Flask app
python src/app.py

Open `http://127.0.0.1:5000` in your browser.
Use the UI:
Paste Email: Enter email text (subject + body) and click "Analyze Email".
Upload File: Upload an .eml or .msg file and click "Analyze File".
View the verdict, confidence, and detailed scores (toggleable).



Notes on the Model
- The backend attempts to load `Model/spam_model.pkl` automatically.
- If your model is a scikit-learn Pipeline with vectorization inside, it will work out of the box.
- If you used a separate vectorizer previously, retrain/export a Pipeline to simplify deployment.

Deployment
For production (e.g., Render, Fly.io):

pip install gunicorn
Procfile (example):
web: gunicorn -w 2 src.app:app

Ensure `Model/` is included and API keys are set as environment variables.
Note: VirusTotal free API has rate limits; cache results in production.

Notes

Dataset: Assumes mails_dataset.csv has a 'text' column for TF-IDF. If your features differ, modify get_model_prob in app.py.
VirusTotal: Scans URLs in emails; a malicious URL flags 100% probability (adjustable).
Error Handling: The app handles empty inputs, invalid file types, and API errors with alerts.
Testing: Use public datasets (e.g., Enron for ham, PhishingCorpus for spam) to verify accuracy.

Dependencies
See `requirements.txt`:

flask==3.0.3
pandas==2.2.2
scikit-learn==1.5.1
joblib==1.4.2
requests==2.32.3
extract-msg==0.42.0
olefile==0.47
compressed-rtf==1.0.6

License
This is belongs to Sharanya. 