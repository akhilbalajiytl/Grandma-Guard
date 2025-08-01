/**
 * GrandmaGuard Security Scan Comparison JavaScript Module
 * 
 * This module provides side-by-side comparison functionality for analyzing
 * multiple security scan results within the GrandmaGuard dashboard. It enables
 * security analysts to compare AI model performance across different scans,
 * configurations, or time periods for comprehensive security assessment.
 * 
 * Core Features:
 * - Parallel loading and display of multiple security scan results
 * - Side-by-side comparison visualization for easy analysis
 * - Statistical summary generation for quick security posture assessment
 * - Detailed result breakdown with status categorization
 * - Responsive UI updates with loading states and error handling
 * 
 * Comparison Capabilities:
 * - Security test pass/fail rate analysis
 * - OWASP category performance comparison
 * - Multi-tool assessment result correlation
 * - Temporal security posture tracking
 * - Model-to-model security effectiveness comparison
 * 
 * Use Cases:
 * - A/B testing of different AI model configurations
 * - Security posture trending over time
 * - Effectiveness validation of security improvements
 * - Compliance reporting with comparative analysis
 * 
 * @author GrandmaGuard Security Team
 * @license MIT
 */

// app/static/js/compare.js

/**
 * Load and display side-by-side comparison of two security scan results.
 * 
 * This function orchestrates the parallel loading and rendering of two
 * security scan results for comparative analysis. It manages the complete
 * workflow from data fetching to UI updates, providing a comprehensive
 * side-by-side view for security assessment comparison.
 * 
 * The function handles:
 * - Parallel data fetching for optimal performance
 * - Loading state management with user feedback
 * - Error handling and graceful degradation
 * - Synchronized rendering of comparison results
 * 
 * @async
 * @example
 * // Load comparison when page loads
 * document.addEventListener('DOMContentLoaded', loadComparison);
 * 
 * @example
 * // Load comparison when user changes selection
 * document.getElementById('runA').addEventListener('change', loadComparison);
 * document.getElementById('runB').addEventListener('change', loadComparison);
 */
async function loadComparison() {
    const runA_id = document.getElementById('runA').value;
    const runB_id = document.getElementById('runB').value;

    const runA_container = document.getElementById('runA-results');
    const runB_container = document.getElementById('runB-results');

    // Show loading message while fetching data
    if (runA_id) runA_container.innerHTML = '<h2>Loading Run A...</h2>';
    if (runB_id) runB_container.innerHTML = '<h2>Loading Run B...</h2>';

    // Fetch and render data in parallel
    const [dataA, dataB] = await Promise.all([
        runA_id ? fetchRunData(runA_id) : Promise.resolve(null),
        runB_id ? fetchRunData(runB_id) : Promise.resolve(null)
    ]);

    renderRunColumn(runA_container, dataA, runA_id);
    renderRunColumn(runB_container, dataB, runB_id);
}

async function fetchRunData(runId) {
    try {
        const response = await fetch(`/api/results/${runId}`);
        if (!response.ok) return null;
        return await response.json();
    } catch (error) {
        console.error("Failed to fetch run data:", error);
        return null;
    }
}

function renderRunColumn(container, data, runId) {
    if (!data) {
        container.innerHTML = ''; // Clear loading message if no data
        return;
    }

    const total = data.detailed_results.length;
    const counts = { PASS: 0, FAIL: 0, PENDING_REVIEW: 0, ERROR: 0 };
    data.detailed_results.forEach(r => {
        if (r.status in counts) counts[r.status]++;
    });

    // Main template for the entire column
    let html = `
        <h2>${escapeHtml(data.scan_name)}</h2>
        <div class="card">
            <h3>Run Summary</h3>
            <ul>
                <li><span>Overall Score</span> <strong>${(data.overall_score * 100).toFixed(1)}%</strong></li>
                <li><span>Passed</span> <strong>${counts.PASS} / ${total}</strong></li>
                <li><span>Failed (Vulnerable)</span> <strong>${counts.FAIL} / ${total}</strong></li>
                <li><span>Pending Review</span> <strong>${counts.PENDING_REVIEW} / ${total}</strong></li>
            </ul>
            <a href="/api/export/${runId}" class="btn">Export to CSV</a>
        </div>
        
        <h3>Detailed Results</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Payload</th>
                    <th>Response</th> 
                    <th>Garak</th>     
                    <th>Llama Guard</th>
                    <th>Judge</th>     
                </tr>
            </thead>
            <tbody>
    `;

    // Populate table rows
    if (total > 0) {
        data.detailed_results.forEach(result => {
            html += `
                <tr>
                    <td>${escapeHtml(result.owasp_category)}</td>
                    <td><span class="status status-${result.status.toLowerCase()}">${escapeHtml(result.status.replace('_', ' '))}</span></td>
                    <td><pre>${escapeHtml(result.payload)}</pre></td>
                    <!-- ADDED THE MODEL RESPONSE CELL -->
                    <td><pre>${escapeHtml(result.response)}</pre></td>
                    <!-- ADDED THE GARAK STATUS CELL -->
                    <td>${escapeHtml(result.garak_status || 'N/A')}</td>
                    <!-- Llama Guard Cell (already existed) -->
                    <td>${formatLlamaGuard(result.llama_guard_status)}</td>
                    <!-- ADDED THE JUDGE STATUS CELL -->
                    <td>${escapeHtml(result.judge_status || 'N/A')}</td>
                </tr>
            `;
        });
    } else {
        html += `<tr><td colspan="7">No detailed results found.</td></tr>`; // Changed colspan to 7
    }

    html += `</tbody></table>`;
    container.innerHTML = html;
}

// Helper function to format the Llama Guard JSON blob into nice HTML
function formatLlamaGuard(lgStatus) {
    if (!lgStatus || typeof lgStatus !== 'object') {
        return '<span style="color: var(--text-muted);">N/A</span>';
    }

    if (lgStatus.status === 'UNSAFE') {
        return `<span style="color: #F87171; font-weight: bold;">UNSAFE</span><br><small style="color: var(--text-muted);">${escapeHtml(lgStatus.category_name)}</small>`;
    }

    if (lgStatus.status === 'SAFE') {
        return `<span style="color: #4ADE80; font-weight: bold;">SAFE</span>`;
    }

    return `<span style="color: #FACC15;">${escapeHtml(lgStatus.status)}</span>`;
}


// Helper function to prevent XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// Add a class to the status span for better styling
function getStatusSpan(status) {
    const statusText = status.replace('_', ' ');
    return `<span class="status status-${status}">${escapeHtml(statusText)}</span>`;
}

// Initial load when the page is ready
document.addEventListener('DOMContentLoaded', loadComparison);