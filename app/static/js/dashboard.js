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
    const response = await fetch(`/api/results/${runId}`);
    const data = await response.json();

    // Update dashboard header with scan information
    document.getElementById('current-model-name').innerText = `Results for: ${data.scan_name}`;

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
        <th>AI Judge Assessment</th>
        <th>Final Security Status</th>
        <th>Review Actions</th>
    `;

    // Populate detailed results table with security assessment data
    const tableBody = document.getElementById('results-tbody');
    tableBody.innerHTML = ''; // Clear existing results

    data.detailed_results.forEach(result => {
        const row = tableBody.insertRow();

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
        const judgeCell = row.insertCell();
        const statusCell = row.insertCell();
        const actionsCell = row.insertCell();

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
        if (lgStatus && lgStatus.status === 'UNSAFE') {
            llamaGuardCell.innerHTML = `<span style="color: #ffb8b8; font-weight: bold;">${lgStatus.status}</span><br><small>(${lgStatus.category_name})</small>`;
            llamaGuardCell.style.fontWeight = 'bold';
        } else if (lgStatus) {
            llamaGuardCell.textContent = lgStatus.status;
        } else {
            llamaGuardCell.textContent = 'N/A';
        }

        // Display AI judge assessment results
        judgeCell.textContent = result.judge_status;

        // Display final security status with emphasis
        statusCell.textContent = result.status;
        statusCell.style.fontWeight = 'bold';

        // Add manual review action buttons for pending assessments
        if (result.status === 'PENDING_REVIEW') {
            actionsCell.innerHTML = `
                <button class="action-btn pass" onclick="submitReview(${result.id}, 'PASS')">Approve (PASS)</button>
                <button class="action-btn fail" onclick="submitReview(${result.id}, 'FAIL')">Reject (FAIL)</button>
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