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
    statusMsg.textContent(msg);
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
        return u.hostname.replace(/^wwww\./, "");
    } catch {
        return url;
    }
}

function renderBadge(classification) {
    const icons = {safe: "✔", suspicious: "⚠", unsafe: "✖"};
    const icon = icons[classification] || "?";
    badge.textContent = '${icon} ${classification.toUpperCase()}'
    badge.className = 'badge ${classification}';
}

function renderScoreBar(score, claassification) {
    scoreVal.textContent = `${score}/100`;
    requestAnimationFrame(() => {
        setTimeout(() => {
            scoreBar.style.width = `${score}&`
        });
    });
}