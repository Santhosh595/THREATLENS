# ThreatLens – Cyber Threat Intelligence Platform

ThreatLens is a web-based cyber security application designed to analyze URLs and detect potential phishing or malicious threats before users interact with them. The system provides explainable threat analysis, helping users understand why a link may be unsafe and what action should be taken.

## 🚀 Features

- URL threat analysis (Safe / Suspicious / Dangerous)
- Detection of common phishing indicators:
  - Missing HTTPS encryption
  - Shortened URLs
  - Login / verification keywords
  - Suspicious URL structures
- Risk level visualization using a dynamic risk bar
- Explainable output with:
  - Threat type
  - Page intent
  - Detected indicators
  - Recommended action
- Link and domain history tracking (detects previously analyzed links)
- Clean, animated, and user-friendly interface
- Can be deployed as a public web application

## 🛠️ Technologies Used

- **Backend:** Python (Flask)
- **Frontend:** HTML, CSS, JavaScript
- **Server:** Gunicorn
- **Deployment:** Render / Railway / PythonAnywhere

## 📂 Project Structure

THREATLENS/
├── app.py
├── requirements.txt
├── templates/
│ └── index.html

yaml
Copy code

## ▶️ How to Run Locally

1. Clone the repository:
git clone https://github.com/Santhosh595/THREATLENS.git

csharp
Copy code
2. Navigate into the project folder:
cd THREATLENS

markdown
Copy code
3. Install dependencies:
pip install -r requirements.txt

markdown
Copy code
4. Run the application:
python app.py

markdown
Copy code
5. Open your browser and visit:
http://127.0.0.1:5000



## 🌐 Deployment

ThreatLens can be deployed as a public website using cloud platforms such as:
- Render
- Railway
- PythonAnywhere

No changes to the core logic are required for deployment.

## 🎯 Purpose

The goal of ThreatLens is to improve cyber awareness and help users avoid phishing attacks, fraudulent websites, and online scams by analyzing links before clicking them.

## 📜 License

This project is licensed under the MIT License.
"# THREATLENS" 
