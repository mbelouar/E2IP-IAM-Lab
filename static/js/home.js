// Navigation function for quick actions
function navigateTo(section) {
    // This would typically route to different sections of the app
    console.log(`Navigating to ${section}`);
    // Show a toast notification
    showToast(`Navigating to ${section.charAt(0).toUpperCase() + section.slice(1)}`);
}

// Toggle user dropdown
function toggleUserMenu() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('userDropdown');
    const userMenu = document.querySelector('.user-menu');
    
    if (dropdown && userMenu) {
        if (!userMenu.contains(event.target) && !dropdown.contains(event.target)) {
            dropdown.classList.remove('show');
        }
    }
});

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    document.body.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Initialize tooltips for SAML attributes
document.addEventListener('DOMContentLoaded', function() {
    // Add tooltips to truncated SAML attributes
    const samlValues = document.querySelectorAll('.saml-attribute-value');
    samlValues.forEach(el => {
        if (el.scrollWidth > el.clientWidth) {
            el.setAttribute('title', el.textContent);
        }
    });
    
    // Initialize any interactive elements
    initInteractiveElements();
});

// Initialize interactive elements
function initInteractiveElements() {
    // Add click handlers for quick access items
    const quickAccessItems = document.querySelectorAll('.quick-access-item');
    quickAccessItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const action = this.querySelector('span').textContent;
            showToast(`${action} clicked`, 'info');
            // Add actual navigation or functionality here
        });
    });
    
    // Add click handlers for app items
    const appItems = document.querySelectorAll('.app-item');
    appItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const appName = this.querySelector('span').textContent;
            if (appName === 'Add App') {
                showToast('Opening app store...', 'info');
            } else {
                showToast(`Opening ${appName}...`, 'info');
            }
            // Add actual app opening logic here
        });
    });
}

// Debounce function for window resize
let resizeTimer;
window.addEventListener('resize', function() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function() {
        // Handle responsive behavior here if needed
    }, 250);
});

// Add smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 20,
                behavior: 'smooth'
            });
        }
    });
});
