/**
* GrandmaGuard Security Dashboard JavaScript Module
* 
* This module provides interactive functionality for the GrandmaGuard security
* assessment dashboard, including test result visualization, data management,
* and user interaction handling for security scan analysis.
* 
* Core Features:
* - Dynamic loading and display of security scan results
* - Interactive Chart.js visualization of OWASP security categories
* - Real-time table population with detailed test results
* - Security status review and approval workflow
* - Responsive UI updates and state management
* 
* Dependencies:
* - Chart.js for data visualization
* - Native Fetch API for backend communication
* - DOM manipulation for dynamic content updates
* 
* Security Assessment Visualization:
* The dashboard presents security scanning results across multiple dimensions:
* - OWASP AI security category mapping
* - Multi-tool assessment results (Garak, LlamaGuard, Judge)
* - Test result status tracking (PASS/FAIL/PENDING_REVIEW/ERROR)
* - Detailed payload and response analysis
* 
* @author GrandmaGuard Security Team
* @license MIT
*/

// app/static/js/dashboard.js

/**
 * Global Chart.js instance for OWASP security category visualization.
 * Destroyed and recreated when switching between different scan results.
 * @type {Chart|null}
 */
let myChart = null;

/**
 * Load and display detailed results for a specific security scan run.
 * 
 * This function fetches comprehensive scan results from the backend API,
 * updates the dashboard UI with new data, and renders both chart and
 * tabular visualizations. It handles the complete workflow of displaying
 * security assessment results for stakeholder review.
 * 
 * The function manages:
 * - Visual indication of active scan selection
 * - Chart destruction and recreation for new data
 * - Comprehensive table population with security status
 * - Color-coded status indicators for quick assessment
 * 
 * @async
 * @param {string|number} runId - Unique identifier for the security scan run
 * 
 * @example
 * // Load results for scan run #123
 * await loadRunDetails(123);
 * 
 * @example
 * // Load results triggered by user selection
 * document.addEventListener('click', (event) => {
 *   if (event.target.classList.contains('run-item')) {
 *     const runId = event.target.dataset.runId;
 *     loadRunDetails(runId);
 *   }
 * });
 */
async function loadRunDetails(runId) {
    // Highlight the active run in the sidebar
    document.querySelectorAll('.run-item').forEach(item => item.classList.remove('active'));
    const activeItem = document.querySelector(`.run-item[data-run-id='${runId}']`);
    if (activeItem) {
        activeItem.classList.add('active');
    }

    const response = await fetch(`/api/results/${runId}`);
    const data = await response.json();

    document.getElementById('current-model-name').innerText = `Results for: ${data.scan_name}`;
    document.getElementById('current-model-score').innerText = `${(data.overall_score * 100).toFixed(1)}%`;

    const ctx = document.getElementById('owasp-chart').getContext('2d');
    if (myChart) {
        myChart.destroy();
    }
    myChart = new Chart(ctx, {
        type: 'bar',
        data: data.chart_data,
        options: { // Chart options are correct, keeping them as is
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, ticks: { color: '#dcdcdc' }, grid: { color: 'rgba(220, 220, 220, 0.1)' } },
                y: { stacked: true, beginAtZero: true, ticks: { color: '#dcdcdc' }, grid: { color: 'rgba(220, 220, 220, 0.1)' } }
            },
            responsive: true,
            plugins: {
                title: { display: true, text: 'Results by Category', color: '#ffffff' },
                legend: { labels: { color: '#dcdcdc' } }
            }
        }
    });

    const tableBody = document.getElementById('results-tbody');
    tableBody.innerHTML = '';

    // --- THIS IS THE NEW LOGIC FOR THE "VIEW DETAILS" BUTTON ---
    // First, determine the correct report URL for the ENTIRE run.
    let reportUrl = `/report/redteam/${runId}`; // Default to red team report
    // If there are results AND the first result's category starts with GARAK_,
    // then we know this is a Garak scan.
    if (data.detailed_results.length > 0 && data.detailed_results[0].owasp_category.startsWith('GARAK_')) {
        reportUrl = `/report/garak/${runId}`;
    }
    // --- END OF NEW LOGIC ---

    data.detailed_results.forEach(result => {
        // --- FIX THE SYNTAX ERROR ---
        const row = tableBody.insertRow();
        // --- END OF FIX ---
        row.id = `result-row-${result.id}`;

        const statusColors = {
            'FAIL': 'rgba(192, 75, 75, 0.2)',
            'PASS': 'rgba(39, 174, 96, 0.2)',
            'ERROR': 'rgba(128, 128, 128, 0.2)',
            'PENDING_REVIEW': 'rgba(241, 196, 15, 0.2)'
        };
        row.style.backgroundColor = statusColors[result.status] || 'transparent';

        const categoryCell = row.insertCell();
        const payloadCell = row.insertCell();
        const responseCell = row.insertCell();
        const garakCell = row.insertCell();
        const llamaGuardCell = row.insertCell();
        const judgeCell = row.insertCell();
        const statusCell = row.insertCell();
        const actionsCell = row.insertCell();

        categoryCell.textContent = result.owasp_category;
        payloadCell.innerHTML = `<pre>${result.payload}</pre>`;
        responseCell.innerHTML = `<pre>${result.response}</pre>`;
        garakCell.textContent = result.garak_status || 'N/A';
        judgeCell.textContent = result.judge_status || 'N/A';

        const lgStatus = result.llama_guard_status;
        if (lgStatus && typeof lgStatus === 'object') {
            if (lgStatus.status === 'UNSAFE') {
                llamaGuardCell.innerHTML = `
                    <div style="color: #F87171; font-weight: bold;">${lgStatus.status}</div>
                    <small style="color: var(--text-muted);">(${lgStatus.category_name || 'No category'})</small>
                `;
            } else {
                const color = lgStatus.status === 'SAFE' ? '#4ADE80' : '#FACC15';
                llamaGuardCell.innerHTML = `<div style="color: ${color}; font-weight: bold;">${lgStatus.status || 'N/A'}</div>`;
            }
        } else {
            llamaGuardCell.textContent = 'N/A';
        }

        statusCell.id = `status-cell-${result.id}`;
        // Use the reportUrl variable we determined earlier
        statusCell.innerHTML = `
            <div style="font-weight: bold;">${result.status}</div>
            <a href="${reportUrl}" class="btn" target="_blank" style="margin-top: 8px; font-size: 0.8em; padding: 6px 10px;">
                View Details
            </a>
        `;

        actionsCell.id = `actions-cell-${result.id}`;
        if (result.status === 'PENDING_REVIEW') {
            actionsCell.innerHTML = `
                <button class="btn" style="background-color: #4ADE80; color: #1E2A2B;" onclick="submitReview(${result.id}, 'PASS')">Approve</button>
                <button class="btn" style="background-color: #F87171; color: #1E2A2B; margin-top: 5px;" onclick="submitReview(${result.id}, 'FAIL')">Reject</button>
            `;
        }
    });
}

/**
 * Submit manual security assessment review for pending test results.
 * 
 * This function handles the manual review workflow for security test results
 * that require human judgment. It communicates with the backend API to update
 * test result status and refreshes the dashboard to reflect the new assessment.
 * 
 * The review system enables security analysts to:
 * - Override automated assessment decisions
 * - Provide manual classification for edge cases
 * - Ensure comprehensive security validation
 * - Maintain audit trails for compliance
 * 
 * @async
 * @param {number} resultId - Unique identifier for the test result
 * @param {string} newStatus - New security status ('PASS' or 'FAIL')
 * 
 * @example
 * // Approve a test result as secure
 * await submitReview(456, 'PASS');
 * 
 * @example
 * // Reject a test result as security violation
 * await submitReview(789, 'FAIL');
 */
async function submitReview(resultId, newStatus) {
    // Submit review decision to backend API
    const response = await fetch(`/api/review/${resultId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus }),
    });

    // Handle review submission response and refresh dashboard
    if (response.ok) {
        // Refresh the currently active scan results to reflect the review
        const activeRunItem = document.querySelector('.run-item.active');
        if (activeRunItem && activeRunItem.dataset.runId) {
            loadRunDetails(activeRunItem.dataset.runId);
        } else {
            // Fallback to full page reload if no active item found
            location.reload();
        }
    } else {
        // Display user-friendly error message for failed submissions
        alert("Failed to submit security review. Please try again.");
    }
}