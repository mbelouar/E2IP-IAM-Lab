// Global state management
const AppState = {
    darkMode: false,
    isLoggedIn: false,
    isLoading: false
};

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    animateBackground();
});

function initializeApp() {
    // Check local storage for theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
        AppState.darkMode = true;
        updateThemeIcon(true);
    }

    // Set up event listeners
    const themeToggleBtn = document.getElementById('themeToggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }

    const helpBtn = document.getElementById('helpBtn');
    if (helpBtn) {
        helpBtn.addEventListener('click', showHelp);
    }

    // Initialize form if present
    const loginForm = document.querySelector('.login-form form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Toggle password visibility
    const togglePasswordBtn = document.querySelector('.toggle-password');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            // Update icon
            const icon = this.querySelector('svg');
            if (type === 'text') {
                icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
            } else {
                icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
            }
        });
    }

    // Create floating elements for background
    createFloatingElements();
    
    // Show welcome message
    showWelcomeMessage();
}

// Theme management
function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    AppState.darkMode = document.body.classList.contains('dark-mode');
    
    // Update localStorage
    localStorage.setItem('theme', AppState.darkMode ? 'dark' : 'light');
    
    // Update theme icon
    updateThemeIcon(AppState.darkMode);
    
    // Show toast
    showToast('Theme Changed', AppState.darkMode ? 'Dark mode activated' : 'Light mode activated', 'info');
}

function updateThemeIcon(isDark) {
    const themeIcon = document.querySelector('#themeToggle svg');
    if (themeIcon) {
        if (isDark) {
            themeIcon.innerHTML = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
        } else {
            themeIcon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
        }
    }
}

// Enhanced background animation
function animateBackground() {
    const floatingElements = document.querySelectorAll('.floating-element');
    
    floatingElements.forEach(element => {
        const speedFactor = Math.random() * 0.5 + 0.5; // Speed between 0.5 and 1
        element.style.animationDuration = 12 / speedFactor + 's';
    });
}

function createFloatingElements() {
    const container = document.querySelector('.floating-elements');
    if (!container) return;
    
    // Already has elements
    if (container.children.length > 0) return;
    
    // Create 4 floating elements
    for (let i = 0; i < 4; i++) {
        const element = document.createElement('div');
        element.className = 'floating-element';
        container.appendChild(element);
    }
}

// Toast notification system
function showToast(title, message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    
    if (!toastContainer) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-header">
            <div class="toast-title">${title}</div>
            <button class="toast-close" onclick="closeToast(this)">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
            </button>
        </div>
        <div class="toast-message">${message}</div>
    `;
    
    toastContainer.appendChild(toast);
    
    // Wait a moment before adding the show class for animation
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Auto close after 5 seconds
    setTimeout(() => {
        closeToast(toast.querySelector('.toast-close'));
    }, 5000);
}

function closeToast(button) {
    const toast = button.closest('.toast');
    toast.classList.remove('show');
    
    // Remove from DOM after animation completes
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 300);
}

// Login handling
function handleLogin(event) {
    // This is where we'll integrate with Django's authentication
    // For now, we'll just simulate a login with a loading state
    
    const form = event.target;
    const username = form.querySelector('#username').value;
    const password = form.querySelector('#password').value;
    
    // Form will be submitted normally to Django view
    // No need to prevent default
    
    // Show loading state
    const loginButton = form.querySelector('.login-button');
    const buttonText = loginButton.querySelector('.button-content');
    
    loginButton.classList.add('loading');
    buttonText.style.opacity = '0';
    
    // We will let Django handle the authentication
    return true;
}

// Security information
function showSecurityInfo(type) {
    let title, message;
    
    switch (type) {
        case 'encryption':
            title = 'End-to-End Encryption';
            message = 'All data transmitted between your browser and our servers is encrypted using industry-standard TLS/SSL protocols.';
            break;
        case 'compliance':
            title = 'GDPR Compliance';
            message = 'Our authentication system is fully compliant with GDPR regulations, ensuring your personal data is protected according to European standards.';
            break;
        case 'monitoring':
            title = '24/7 Monitoring';
            message = 'Our security team continuously monitors for suspicious activity and potential threats to keep your account secure.';
            break;
        default:
            title = 'Security Information';
            message = 'Your security is our priority. We implement industry best practices to protect your account.';
    }
    
    showToast(title, message, 'info');
}

// Utility functions
function logoClick() {
    // Animated logo interaction
    const logo = document.querySelector('.logo');
    if (logo) {
        logo.style.transform = 'scale(0.95) rotate(-10deg)';
        setTimeout(() => {
            logo.style.transform = '';
        }, 300);
    }
    
    showToast('SecureAuth', 'Enterprise Identity and Access Management', 'info');
}

function showHelp() {
    showToast('Need Help?', 'Contact IT support at support@example.com or call ext. 1234 for assistance with login issues.', 'info');
}

function showWelcomeMessage() {
    setTimeout(() => {
        showToast('Welcome', 'Sign in to access your secure enterprise applications', 'info');
    }, 1000);
}

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Alt+T to toggle theme
    if (event.altKey && event.key === 't') {
        toggleTheme();
    }
    
    // Alt+H for help
    if (event.altKey && event.key === 'h') {
        showHelp();
    }
});

// Connection monitoring
window.addEventListener('online', () => {
    showToast('Connection Restored', 'Internet connection has been restored', 'success');
});

window.addEventListener('offline', () => {
    showToast('Connection Lost', 'You are currently offline. Authentication may not be available.', 'error');
});

// Performance monitoring
window.addEventListener('load', function() {
    // Example of measuring performance
    const loadTime = window.performance.timing.domContentLoadedEventEnd - window.performance.timing.navigationStart;
    console.log('Page loaded in: ' + loadTime + 'ms');
});
