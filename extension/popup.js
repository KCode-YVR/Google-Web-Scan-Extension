const BACKEND_URL = "http://localhost:5000/scan";

const initialState = document.getElementById("initial-state");
const resultState = document.getElementById("result-state");
const scanButton = document.getElementById("scan-button");
const rescanButton = document.getElementById("rescan-button");
const statusMsg = document.getElementById("status-msg");
const resDomain = document.getElementById("res-domain");
const badge = document.getElementById("classification-badge");
const scoreVal = document.getElementById("score-value");
const scoreBar = document.getElementById("score-bar");
const reasonsList = document.getElementById("reasons-list");
const wsCreation = document.getElementById("ws-creation");
const wsExpiration = document.getElementById("ws-expiration");
const wsUpdated = document.getElementById("ws-updated");
const wsRegistrar = document.getElementById("ws-registrar");

function setStatus(msg) {
    statusMsg.textContent = msg;
}

function setLoading(isLoading) {
        if (isLoading) {
            scanButton.disabled = true;
            scanButton.innerHTML = `<span class="spinner"></span> Scanning...`;
            setStatus("Contacting local backend...");
        } else {
            scanButton.disabled = false;
            scanButton.innerHTML = `<span class="button-icon">▶</span> Run WHOIS Scan`;
            setStatus(" ");
        }
}

function showInitialState() {
    initialState.classList.remove("hidden");
    resultState.classList.add("hidden");
}

function showResultState() {
    resultState.classList.remove("hidden");
    initialState.classList.add("hidden");
}

function extractDomain(url) {
    try {
        const u = new URL(url);
        return u.hostname.replace(/^www\./, "");
    } catch {
        return url;
    }
}

function renderBadge(classification) {
    const icons = {safe: "✔", suspicious: "⚠", unsafe: "✖"};
    const icon = icons[classification] || "?";
    badge.textContent = `${icon}  ${classification.toUpperCase()}`
    badge.className = `badge ${classification}`;
}

function renderScoreBar(score, classification) {
    scoreVal.textContent = `${score}/100`;
    requestAnimationFrame(() => {
        setTimeout(() => {
            scoreBar.style.width = `${score}%`;
            scoreBar.className = `score-bar ${classification}`;
        }, 60);
    });
}

function renderReasons(reasons) {
    reasonsList.innerHTML = "";
    if (!reasons || reasons.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No specific reasons returned.";
        reasonsList.appendChild(li);
        return;
    }
    for (const reason of reasons) {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsList.appendChild(li);
    }
}

function renderWhoisSummary(summary) {
    wsCreation.textContent   = summary.creation   || "Unknown";
    wsExpiration.textContent = summary.expiration || "Unknown";
    wsUpdated.textContent    = summary.updated    || "Unknown";
    wsRegistrar.textContent  = summary.registrar  || "Unknown";
}

function renderResult(data) {
    resDomain.textContent = data.domain;
    renderBadge(data.classification);
    renderScoreBar(data.risk_score, data.classification);
    renderReasons(data.reasons);
    renderWhoisSummary(data.whois_summary);
    showResultState();
}

function showError(message) {
    setLoading(false);
    setStatus(`⚠ ${message}`);
    statusMsg.style.color = "#f74f4f";
}

async function runScan() {
    statusMsg.style.color = "";
    setLoading(true);

    let tabURL;
    try {
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        if (!tab || !tab.url) {
            throw new Error("Could not read the current tab's URL.")
        }
        tabURL = tab.url;
    } catch (error) {
        showError("Cannot read active tab. Make sure you're on a regular tab.");
        return;
    }
    
    if (!tabURL.startsWith("https://") && !tabURL.startsWith("http://")) {
        showError("Only http/https pages can get scanned.");
        return;
    }

    const domain = extractDomain(tabURL);
    setStatus(`Scanning ${domain}...`);

    let data;
    try {
        const response = await fetch(BACKEND_URL, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({domain}),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || `Backend returned HTTP ${response.status}`);
        }

        data = await response.json();
    } catch (error) {
        if (error.message.includes("Failed to fetch") || error.message.includes("NetworkError")) {
            showError("Cannot reach backend. Make sure you ran: python app.py");
        } else {
            showError(error.message || "Unknown error from backend");
        }
        return;
    }

    setLoading(false);
    renderResult(data);
}

scanButton.addEventListener("click", runScan);

rescanButton.addEventListener("click", () => {
    showInitialState();
    setLoading(false);
    statusMsg.style.color = "";
    scoreBar.style.width = "0";
})