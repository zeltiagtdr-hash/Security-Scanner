const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultsContent = document.getElementById('results-content');

scanBtn.addEventListener('click', startScan);

async function startScan() {
    const url = urlInput.value.trim();
    
    if (!url) {
        alert('Silakan masukkan URL website terlebih dahulu!');
        return;
    }

    if (!isValidUrl(url)) {
        alert('URL tidak valid! Pastikan format URL benar (contoh: https://example.com)');
        return;
    }

    showLoading();
    hideResults();

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        displayResults(data);
    } catch (error) {
        console.error('Error:', error);
        displayError('Terjadi kesalahan saat memindai website. Silakan coba lagi.');
    }

    hideLoading();
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function showLoading() {
    loading.classList.remove('hidden');
    scanBtn.disabled = true;
}

function hideLoading() {
    loading.classList.add('hidden');
    scanBtn.disabled = false;
}

function showResults() {
    results.classList.remove('hidden');
}

function hideResults() {
    results.classList.add('hidden');
}

function displayResults(data) {
    let html = '';
    
    if (data.error) {
        html = `<div class="vulnerability-card high">
            <div class="vulnerability-header">
                <span class="vulnerability-name">❌ Error</span>
                <span class="severity-badge high">High</span>
            </div>
            <div class="vulnerability-description">${data.error}</div>
        </div>`;
    } else {
        data.forEach(item => {
            html += createVulnerabilityCard(item);
        });
    }

    resultsContent.innerHTML = html;
    showResults();
}

function displayError(message) {
    const html = `<div class="vulnerability-card high">
        <div class="vulnerability-header">
            <span class="vulnerability-name">❌ Error</span>
            <span class="severity-badge high">High</span>
        </div>
        <div class="vulnerability-description">${message}</div>
    </div>`;
    
    resultsContent.innerHTML = html;
    showResults();
}

function createVulnerabilityCard(item) {
    const icon = item.status === 'vulnerable' ? '⚠️' : '✅';
    
    return `<div class="vulnerability-card ${item.severity}">
        <div class="vulnerability-header">
            <span class="vulnerability-name">${icon} ${item.name}</span>
            <span class="severity-badge ${item.severity}">${item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}</span>
        </div>
        <div class="vulnerability-description">${item.description}</div>
    </div>`;
}
