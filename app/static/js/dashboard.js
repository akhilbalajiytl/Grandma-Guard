// app/static/js/dashboard.js
let myChart = null;

async function loadRunDetails(runId) {
    // --- Add active class to the clicked item ---
    document.querySelectorAll('.run-item').forEach(item => item.classList.remove('active'));
    const activeItem = document.querySelector(`.run-item[data-run-id='${runId}']`);
    if (activeItem) {
        activeItem.classList.add('active');
    }

    const response = await fetch(`/api/results/${runId}`);
    const data = await response.json();

    document.getElementById('current-model-name').innerText = `Results for: ${data.scan_name}`;

    const ctx = document.getElementById('owasp-chart').getContext('2d');
    if (myChart) {
        myChart.destroy();
    }

    // --- THIS IS THE RESTORED, CORRECT CHART CONFIGURATION ---
    myChart = new Chart(ctx, {
        type: 'bar',
        data: data.chart_data, // Use the data from our API
        options: {
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true,
                    ticks: { color: '#dcdcdc' },
                    grid: { color: 'rgba(220, 220, 220, 0.1)' }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: { color: '#dcdcdc' },
                    grid: { color: 'rgba(220, 220, 220, 0.1)' }
                }
            },
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Test Results by Category',
                    color: '#ffffff'
                },
                legend: {
                    labels: { color: '#dcdcdc' }
                }
            }
        }
    });

    // --- The table logic from before is correct ---
    const tableHead = document.querySelector('#results-table thead tr');
    tableHead.innerHTML = `
        <th>Category</th>
        <th>Payload</th>
        <th>Response</th>
        <th>Garak</th>
        <th>Llama Guard</th>
        <th>Judge</th>
        <th>Final Status</th>
        <th>Actions</th>
    `;

    const tableBody = document.getElementById('results-tbody');
    tableBody.innerHTML = '';

    data.detailed_results.forEach(result => {
        const row = tableBody.insertRow();

        switch (result.status) {
            case 'FAIL': row.style.backgroundColor = 'rgba(192, 75, 75, 0.2)'; break;
            case 'PASS': row.style.backgroundColor = 'rgba(39, 174, 96, 0.2)'; break;
            case 'ERROR': row.style.backgroundColor = 'rgba(128, 128, 128, 0.2)'; break;
            case 'PENDING_REVIEW': row.style.backgroundColor = 'rgba(241, 196, 15, 0.2)'; break;
            default: row.style.backgroundColor = 'transparent';
        }

        const categoryCell = row.insertCell();
        const payloadCell = row.insertCell();
        const responseCell = row.insertCell();
        // const baselineCell = row.insertCell();
        const garakCell = row.insertCell();
        const llamaGuardCell = row.insertCell();
        const judgeCell = row.insertCell();
        const statusCell = row.insertCell();
        const actionsCell = row.insertCell();

        categoryCell.textContent = result.owasp_category;

        const payloadPre = document.createElement('pre');
        payloadPre.textContent = result.payload;
        payloadCell.appendChild(payloadPre);

        const responsePre = document.createElement('pre');
        responsePre.textContent = result.response;
        responseCell.appendChild(responsePre);

        // baselineCell.textContent = result.baseline_status;
        garakCell.textContent = result.garak_status || 'N/A';

        const lgStatus = result.llama_guard_status;
        if (lgStatus && lgStatus.status === 'UNSAFE') {
            llamaGuardCell.innerHTML = `<span style="color: #ffb8b8; font-weight: bold;">${lgStatus.status}</span><br><small>(${lgStatus.category_name})</small>`;
            llamaGuardCell.style.fontWeight = 'bold';
        } else if (lgStatus) {
            llamaGuardCell.textContent = lgStatus.status;
        } else {
            llamaGuardCell.textContent = 'N/A';
        }

        judgeCell.textContent = result.judge_status;
        statusCell.textContent = result.status;
        statusCell.style.fontWeight = 'bold';

        if (result.status === 'PENDING_REVIEW') {
            actionsCell.innerHTML = `
                <button class="action-btn pass" onclick="submitReview(${result.id}, 'PASS')">Approve (PASS)</button>
                <button class="action-btn fail" onclick="submitReview(${result.id}, 'FAIL')">Reject (FAIL)</button>
            `;
        }
    });
}

async function submitReview(resultId, newStatus) {
    const response = await fetch(`/api/review/${resultId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus }),
    });

    if (response.ok) {
        const activeRunItem = document.querySelector('.run-item.active');
        if (activeRunItem && activeRunItem.dataset.runId) {
            loadRunDetails(activeRunItem.dataset.runId);
        } else {
            location.reload();
        }
    } else {
        alert("Failed to submit review. Please try again.");
    }
}