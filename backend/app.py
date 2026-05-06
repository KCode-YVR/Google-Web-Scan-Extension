from flask import Flask, request, jsonify 
from flask_cors import CORS
from whois_scanner import lookup
from scorer import score

app = Flask(__name__)
CORS(app)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    domain_input = (data.get("domain") or "").strip()
    
    if not domain_input:
        return jsonify({"error": "No domain provided."}), 400
    
    whois_result = lookup(domain_input)
    domain = whois_result["domain"]

    if whois_result["error"] or whois_result["raw"] is None:
        return jsonify({
            "domain": domain,
            "classification": "suspicious",
            "risk_score": 50,
            "reasons": [
                "WHOIS lookup failed or returned no data.",
                whois_result.get("error", "Unknown error."),
                "Cannot assess domain safety without WHOIS data.",
            ],
            "whois_summary": {
                "creation": "Unknown",
                "expiration": "Unknown",
                "updated": "Unknown",
                "registrar": "Unknown",
            },
        })
    result = score(whois_result["raw"])

    return jsonify({
        "domain": domain,
        "classification": result["classification"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "whois_summary": result["whois_summary"],
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "google-web-scan"
    })

if __name__ == "__main__":
    print("=" * 55)
    print("  Google-Web-Scan backend running on port 5000")
    print("  Press Ctrl+C to stop.")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5000, debug=False)