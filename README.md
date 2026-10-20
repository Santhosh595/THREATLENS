# THREATLENS

A lightweight web app that analyzes URLs for phishing indicators before you click them. Paste a link, get an explainable risk verdict — the indicators that drove the decision, the page intent, and a recommended action.

## How it works

`app.py` scores each URL against a small set of phishing heuristics and buckets the result into one of three threat levels:

| Threat level | Risk score | Meaning |
|---|---|---|
| Safe | < 40 | No meaningful indicators found |
| Suspicious Link | 40–69 | Some phishing characteristics present |
| Credential Phishing | ≥ 70 | Strong login / credential-theft patterns |

Each analysis checks the following indicators (all add to the risk score, which starts at 10 and caps at 100):

- **No HTTPS encryption** (+20) — the URL scheme is not `https`
- **Shortened URL** (+30) — `bit.ly`, `tinyurl`, `t.co`, `goo.gl` in the URL
- **Login / verification keyword** (+25) — `login`, `verify`, `update`, `secure` in the URL
- **IP-based URL** (+30) — the host is a raw numeric IP
- **Punycode / Homograph Host** (+30) — any dot-separated host label starting with `xn--` (raw unicode hosts are normalized via IDNA first); possible lookalike of another site, the indicator shows what the label decodes to

Every analysis also records the link and its domain, so repeat visits show whether the exact URL (or just the domain) was checked before, and what it was classified as. This history lives in memory and resets when the process restarts.

## Features

- URL threat analysis with explainable output: threat type, page intent, detected indicators, recommended action
- Animated risk-bar visualization (green → yellow → red)
- Link and domain history tracking within the running process
- Single-page interface, no database required

## Project structure

```
THREATLENS/
├── app.py            # Flask app + URL analysis logic (entry point)
├── app/              # Flask app-factory scaffolding (SQLAlchemy models)
│   ├── __init__.py
│   └── models.py
├── templates/
│   └── index.html    # Single-page UI
├── requirements.txt
├── .env.example
└── LICENSE           # MIT
```

## Run locally

Requires Python 3.8+.

```bash
git clone https://github.com/Santhosh595/THREATLENS.git
cd THREATLENS

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python app.py
```

Then open <http://127.0.0.1:5000> in your browser.

## Deployment

The app is a plain Flask app and deploys as-is to Render, Railway, or PythonAnywhere. For production, serve it with Gunicorn:

```bash
gunicorn app:app
```

## License

MIT — see [LICENSE](LICENSE).
