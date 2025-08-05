// app/static/js/red_team_report.js
function toggleDetails(headerElement) {
    // Find the next sibling element, which is our details container
    const details = headerElement.nextElementSibling;

    // Toggle the visibility classes on the container
    details.classList.toggle('details-visible');

    // Also toggle a class on the header to rotate the icon
    headerElement.classList.toggle('details-hidden');

    // Toggle the icon itself
    const icon = headerElement.querySelector('.expand-icon');
    if (icon) {
        icon.textContent = headerElement.classList.contains('details-hidden') ? '▶' : '▼';
    }
}