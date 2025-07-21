// app/static/js/compare.js

async function loadComparison() {
    const runA_id = document.getElementById('runA').value;
    const runB_id = document.getElementById('runB').value;

    const runA_container = document.getElementById('runA-results');
    const runB_container = document.getElementById('runB-results');

    // Clear previous results
    runA_container.innerHTML = '';
    runB_container.innerHTML = '';

    if (runA_id) {
        const runA_data = await fetchRunData(runA_id);
        renderRunColumn(runA_container, runA_data, runA_id);
    }
    if (runB_id) {
        const runB_data = await fetchRunData(runB_id);
        renderRunColumn(runB_container, runB_data, runB_id);
    }
}

async function fetchRunData(runId) {
    const response = await fetch(`/api/results/${runId}`);
    if (!response.ok) return null;
    return await response.json();
}

// In compare.js, replace the old renderRunColumn function...
function renderRunColumn(container, data, runId) { // Added runId parameter
    if (!data) {
        container.innerHTML = '<h2>Error: Could not load run data.</h2>';
        return;
    }

    const total = data.detailed_results.length;

    // Calculate pass/fail/etc counts
    const counts = { PASS: 0, FAIL: 0, PENDING_REVIEW: 0, ERROR: 0 };
    data.detailed_results.forEach(r => {
        if (r.status in counts) {
            counts[r.status]++;
        }
    });

    // --- Create the HTML for the column ---
    let html = `
        <h2>${escapeHtml(data.scan_name)}</h2>
        <div class="summary-card">
            <h3>Run Summary</h3>
            <ul>
                <li><span>Overall Score</span> <strong>${(data.overall_score * 100).toFixed(1)}%</strong></li>
                <li><span>Passed</span> <strong>${counts.PASS} / ${total}</strong></li>
                <li><span>Failed (Vulnerable)</span> <strong>${counts.FAIL} / ${total}</strong></li>
                <li><span>Pending Review</span> <strong>${counts.PENDING_REVIEW} / ${total}</strong></li>
                <li><span>Errors</span> <strong>${counts.ERROR} / ${total}</strong></li>
            </ul>
            <!-- SAFE EXPORT BUTTON: Uses the reliable runId -->
            <a href="/api/export/${runId}" class="export-btn">Export Results to CSV</a>
        </div>
        
        <h3>Detailed Results</h3>
        <table id="results-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>
    `;

    // Only try to build the table if there are results
    if (total > 0) {
        data.detailed_results.forEach(result => {
            let rowColor = 'transparent';
            switch (result.status) {
                case 'FAIL': rowColor = 'rgba(192, 75, 75, 0.2)'; break;
                case 'PASS': rowColor = 'rgba(39, 174, 96, 0.2)'; break;
                case 'ERROR': rowColor = 'rgba(128, 128, 128, 0.2)'; break;
                case 'PENDING_REVIEW': rowColor = 'rgba(241, 196, 15, 0.2)'; break;
            }

            html += `
                <tr style="background-color: ${rowColor};">
                    <td>${escapeHtml(result.owasp_category)}</td>
                    <td style="font-weight: bold;">${escapeHtml(result.status)}</td>
                    <td><pre>${escapeHtml(result.payload)}</pre></td>
                    <td>${escapeHtml(JSON.stringify(result.llama_guard_status))}</td>
                </tr>
            `;
        });
    } else {
        html += `<tr><td colspan="3">No detailed results found for this run.</td></tr>`;
    }

    html += `</tbody></table>`;
    container.innerHTML = html;
}

// Simple HTML escaping function to prevent XSS in this new display
function escapeHtml(unsafe) {
    // Ensure the input is a string
    if (typeof unsafe !== 'string') {
        // If it's not a string (e.g., null, undefined), return an empty string
        return '';
    }

    // Replace special HTML characters with their corresponding entities
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
