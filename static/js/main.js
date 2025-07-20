/**
 * ADFS Authentication Demo
 * Main JavaScript file
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips if any
    const tooltips = document.querySelectorAll('[data-tooltip]');
    if (tooltips.length > 0) {
        tooltips.forEach(tooltip => {
            tooltip.addEventListener('mouseover', showTooltip);
            tooltip.addEventListener('mouseout', hideTooltip);
        });
    }

    // Collapsible sections
    const collapsibles = document.querySelectorAll('.collapsible-header');
    if (collapsibles.length > 0) {
        collapsibles.forEach(header => {
            header.addEventListener('click', toggleSection);
        });
    }

    // Add active class to current nav item if any
    highlightCurrentNavItem();

    // Log authentication success if we have a success message
    const successMessage = document.querySelector('.auth-success');
    if (successMessage) {
        console.log('Authentication successful');
        
        // Add animation to the success message
        successMessage.classList.add('animated');
        
        // Auto-hide success message after 5 seconds
        setTimeout(() => {
            successMessage.style.opacity = '0';
            setTimeout(() => {
                successMessage.style.display = 'none';
            }, 500);
        }, 5000);
    }
});

// Function to highlight the current page in navigation
function highlightCurrentNavItem() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('nav a');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}

// Function to toggle collapsible sections
function toggleSection(event) {
    const header = event.currentTarget;
    const content = header.nextElementSibling;
    
    if (content.style.maxHeight) {
        content.style.maxHeight = null;
        header.classList.remove('active');
    } else {
        content.style.maxHeight = content.scrollHeight + 'px';
        header.classList.add('active');
    }
}

// Tooltip functions
function showTooltip(event) {
    const element = event.currentTarget;
    const tooltipText = element.getAttribute('data-tooltip');
    
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    
    document.body.appendChild(tooltip);
    
    const elementRect = element.getBoundingClientRect();
    tooltip.style.top = (elementRect.top - tooltip.offsetHeight - 10) + 'px';
    tooltip.style.left = (elementRect.left + (elementRect.width / 2) - (tooltip.offsetWidth / 2)) + 'px';
    tooltip.style.opacity = '1';
    
    element.tooltip = tooltip;
}

function hideTooltip(event) {
    const element = event.currentTarget;
    if (element.tooltip) {
        element.tooltip.remove();
    }
}

// Helper function to handle AJAX requests if needed
async function fetchData(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching data:', error);
        return null;
    }
}
