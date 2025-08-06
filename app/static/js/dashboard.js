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
    // Fetch scan results from backend API
    // Highlight the active run in the sidebar
    document.querySelectorAll('.run-item').forEach(item => item.classList.remove('active'));
    document.querySelector(`.run-item[data-run-id='${runId}']`).classList.add('active');

    const response = await fetch(`/api/results/${runId}`);
    const data = await response.json();

    document.getElementById('current-model-name').innerText = `Results for: ${data.scan_name}`;
    // We will add a new element to display the score
    document.getElementById('current-model-score').innerText = `${(data.overall_score * 100).toFixed(1)}%`;

    // Initialize Chart.js context and destroy existing chart if present
    const ctx = document.getElementById('owasp-chart').getContext('2d');
    if (myChart) {
        myChart.destroy(); // Prevent memory leaks from multiple chart instances
    }

    // Create comprehensive OWASP security category visualization
    myChart = new Chart(ctx, {
        type: 'bar',
        data: data.chart_data, // Structured data from backend API
        options: {
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true, // Stack security categories for comparison
                    ticks: { color: '#dcdcdc' },
                    grid: { color: 'rgba(220, 220, 220, 0.1)' }
                },
                y: {
                    stacked: true, // Stack pass/fail results
                    beginAtZero: true,
                    ticks: { color: '#dcdcdc' },
                    grid: { color: 'rgba(220, 220, 220, 0.1)' }
                }
            },
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Security Assessment Results by OWASP Category',
                    color: '#ffffff'
                },
                legend: {
                    labels: { color: '#dcdcdc' }
                }
            }
        }
    });

    // Initialize comprehensive results table structure
    const tableHead = document.querySelector('#results-table thead tr');
    tableHead.innerHTML = `
        <th>Security Category</th>
        <th>Test Payload</th>
        <th>AI Response</th>
        <th>Garak Analysis</th>
        <th>LlamaGuard Classification</th>
        <th>AI Judge Assessment (gpt-4o-mini)</th>
        <th>Final Security Status</th>
        <th>Review Actions</th>
    `;

    // Populate detailed results table with security assessment data
    const tableBody = document.getElementById('results-tbody');
    tableBody.innerHTML = ''; // Clear existing results

    data.detailed_results.forEach(result => {
        const row = tableBody.insertRow();
        row.id = `result-row-${result.id}`;
        // Apply color-coded status indicators for quick security assessment
        switch (result.status) {
            case 'FAIL':
                row.style.backgroundColor = 'rgba(192, 75, 75, 0.2)'; // Red for security failures
                break;
            case 'PASS':
                row.style.backgroundColor = 'rgba(39, 174, 96, 0.2)'; // Green for secure responses
                break;
            case 'ERROR':
                row.style.backgroundColor = 'rgba(128, 128, 128, 0.2)'; // Gray for system errors
                break;
            case 'PENDING_REVIEW':
                row.style.backgroundColor = 'rgba(241, 196, 15, 0.2)'; // Yellow for manual review
                break;
            default:
                row.style.backgroundColor = 'transparent';
        }

        // Create table cells for comprehensive security result display
        const categoryCell = row.insertCell();
        const payloadCell = row.insertCell();
        const responseCell = row.insertCell();
        const garakCell = row.insertCell();
        const llamaGuardCell = row.insertCell();
        const judgeCell = row.insertCell(); // This cell is for 'judge_status'
        const statusCell = row.insertCell();
        const actionsCell = row.insertCell();

        // Give the status and actions cells IDs so we can easily update them
        statusCell.id = `status-cell-${result.id}`;
        actionsCell.id = `actions-cell-${result.id}`;

        // Populate security category information
        categoryCell.textContent = result.owasp_category;

        // Display test payload with preserved formatting
        const payloadPre = document.createElement('pre');
        payloadPre.textContent = result.payload;
        payloadCell.appendChild(payloadPre);

        // Display AI model response with preserved formatting
        const responsePre = document.createElement('pre');
        responsePre.textContent = result.response;
        responseCell.appendChild(responsePre);

        // Display Garak security analysis results
        garakCell.textContent = result.garak_status || 'N/A';

        // Enhanced LlamaGuard status display with category information
        const lgStatus = result.llama_guard_status;

        // Create a more structured and styled display for the Llama Guard result
        if (lgStatus && typeof lgStatus === 'object') {
            if (lgStatus.status === 'UNSAFE') {
                // For UNSAFE, show the status prominently and the category below it.
                // Use color-coding for at-a-glance understanding.
                llamaGuardCell.innerHTML = `
                <div style="color: #F87171; font-weight: bold;">${lgStatus.status}</div>
                <small style="color: var(--text-muted);">(${lgStatus.category_name || 'No category'})</small>
            `;
            } else if (lgStatus.status === 'SAFE') {
                // For SAFE, just show a green "SAFE" status.
                llamaGuardCell.innerHTML = `<div style="color: #4ADE80; font-weight: bold;">${lgStatus.status}</div>`;
            } else {
                // Handle other statuses like SKIPPED or ERROR
                llamaGuardCell.innerHTML = `<div style="color: #FACC15;">${lgStatus.status || 'Unknown'}</div>`;
                if (lgStatus.reason) {
                    llamaGuardCell.innerHTML += `<br><small style="color: var(--text-muted);">(${lgStatus.reason})</small>`;
                }
            }
        } else {
            // Fallback for missing or malformed data
            llamaGuardCell.textContent = 'N/A';
        }

        // Display AI judge assessment results
        judgeCell.textContent = result.judge_status || 'N/A'; // Let's ensure judge_status is populated
        statusCell.textContent = result.status;
        statusCell.style.fontWeight = 'bold';

        // Populate Final Security Status and the "View Full Report" link together
        statusCell.innerHTML = `
            <div style="font-weight: bold;">${result.status}</div>
            <a href="/report/redteam/${runId}?result_id=${result.id}" class="btn" target="_blank" style="margin-top: 8px; font-size: 0.8em; padding: 6px 10px;">
                View Details
            </a>
        `;

        // Review Actions column is now ONLY for buttons
        let actionsHTML = '';
        if (result.status === 'PENDING_REVIEW') {
            actionsHTML = `
                <button class="btn" style="background-color: #4ADE80; color: #1E2A2B;" onclick="submitReview(${result.id}, 'PASS')">Approve</button>
                <button class="btn" style="background-color: #F87171; color: #1E2A2B; margin-top: 5px;" onclick="submitReview(${result.id}, 'FAIL')">Reject</button>
            `;
        }
        actionsCell.innerHTML = actionsHTML;
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
async function submitReview(resultId, newStatus, runId) {
    // 1. Visually disable the buttons to prevent double-clicking
    const actionCell = document.getElementById(`actions-cell-${resultId}`);
    actionCell.innerHTML = 'Submitting...';

    // 2. Send the request to the backend
    const response = await fetch(`/api/review/${resultId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
    });

    if (response.ok) {
        const data = await response.json(); // The API now returns the new score

        // 3. Update the UI directly - NO PAGE RELOAD

        // Update the row's background color
        const row = document.getElementById(`result-row-${resultId}`);
        row.style.backgroundColor = newStatus === 'PASS'
            ? 'rgba(39, 174, 96, 0.2)'
            : 'rgba(192, 75, 75, 0.2)';

        // Update the status text in the status cell
        const statusCell = document.getElementById(`status-cell-${resultId}`);
        // We find the div inside the cell and update its text
        statusCell.querySelector('div').textContent = newStatus;

        // Clear the action buttons from the actions cell
        actionCell.innerHTML = '';

        // Update the overall score at the top of the page
        document.getElementById('current-model-score').innerText = `${(data.new_run_score * 100).toFixed(1)}%`;

        // Optional: We can also re-fetch just the chart data to update it,
        // but for now, this provides a great user experience.

    } else {
        alert("Failed to submit review. Please try again.");
        // Restore the buttons if the request failed
        actionCell.innerHTML = `
            <button class="btn pass" onclick="submitReview(${resultId}, 'PASS', ${runId})">Approve</button>
            <button class="btn fail" onclick="submitReview(${resultId}, 'FAIL', ${runId})">Reject</button>
        `;
    }
}

function addFollowUpField() {
    const container = document.getElementById('follow-up-container');
    const newField = document.createElement('div');
    newField.style.marginTop = '0.5rem';

    // Create a textarea for the follow-up prompt
    const textarea = document.createElement('textarea');
    textarea.name = 'follow_up_payloads'; // Use the same name for all
    textarea.rows = 2;
    textarea.placeholder = `Follow-up Prompt #${container.children.length + 1}`;
    textarea.style.width = '100%';

    // Create a remove button
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.textContent = 'Remove';
    removeBtn.className = 'btn';
    removeBtn.style.fontSize = '0.7em';
    removeBtn.style.padding = '4px 8px';
    removeBtn.style.backgroundColor = '#F87171';
    removeBtn.style.color = '#1E2A2B';
    removeBtn.style.marginLeft = '5px';
    removeBtn.onclick = function () {
        container.removeChild(newField);
    };

    const wrapper = document.createElement('div');
    wrapper.style.display = 'flex';
    wrapper.style.alignItems = 'center';

    wrapper.appendChild(textarea);
    wrapper.appendChild(removeBtn);
    newField.appendChild(wrapper);
    container.appendChild(newField);
}