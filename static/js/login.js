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
    
    // No default login option selected - let user choose
});

function initializeApp() {
    // Check local storage for theme preference, default to dark
    const savedTheme = localStorage.getItem('theme');
    const isDarkMode = savedTheme ? savedTheme === 'dark' : true; // Default to dark mode
    
    if (isDarkMode) {
        document.body.classList.add('dark-mode');
        AppState.darkMode = true;
        updateThemeIcon(true);
        // Set default theme in localStorage if not set
        if (!savedTheme) {
            localStorage.setItem('theme', 'dark');
        }
    } else {
        document.body.classList.remove('dark-mode');
        AppState.darkMode = false;
        updateThemeIcon(false);
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
    
    // Show welcome message only on login page and home page
    if (window.location.pathname.includes('login') || window.location.pathname.includes('auth_choice') || window.location.pathname === '/' || window.location.pathname.includes('home')) {
        showWelcomeMessage();
    }
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

// Login form toggle
function toggleLoginForm(loginType) {
    const standardForm = document.getElementById('standardLoginForm');
    const ssoForm = document.getElementById('ssoLoginForm');
    const standardBtn = document.getElementById('standardLoginBtn');
    const ssoBtn = document.getElementById('ssoLoginBtn');
    
    if (loginType === 'standard') {
        standardForm.style.display = 'block';
        ssoForm.style.display = 'none';
        standardBtn.classList.add('active');
        ssoBtn.classList.remove('active');
    } else {
        standardForm.style.display = 'none';
        ssoForm.style.display = 'block';
        standardBtn.classList.remove('active');
        ssoBtn.classList.add('active');
    }
}

// Generic login handler that determines the login type
function handleLogin(event) {
    event.preventDefault();
    
    // Determine which form is being submitted
    const form = event.target;
    const isStandardForm = form.closest('#standardLoginForm');
    const isSSOForm = form.closest('#ssoLoginForm');
    
    if (isStandardForm) {
        return handleStandardLogin(event);
    } else if (isSSOForm) {
        // Handle SSO login - redirect to SSO endpoint
        window.location.href = '/auth/sso/login/';
        return false;
    }
    
    return false;
}

// Login handling for standard login
function handleStandardLogin(event) {
    // This is where we'll integrate with Django's authentication
    // For now, we'll just simulate a login with a loading state
    
    const form = event.target;
    const username = form.querySelector('#username').value;
    const password = form.querySelector('#password').value;
    
    if (!username || !password) {
        showToast('Error', 'Please enter both username and password', 'error');
        event.preventDefault();
        return false;
    }
    
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
        case 'sso':
            title = 'Enterprise SSO';
            message = 'Our Single Sign-On solution integrates with your organization\'s identity provider, enabling secure and convenient access to all enterprise applications with just one login.';
            break;
        case 'mfa':
            title = 'MultiFactor Authentication';
            message = 'Add an extra layer of security to your account with MultiFactor Authentication, which requires multiple forms of verification before granting access.';
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
    // Remove existing modal if any
    const existingModal = document.getElementById('helpModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create help modal content
    const modalHTML = `
        <div id="helpModal" class="help-modal" style="display: block;">
            <div class="help-modal-content">
                <div class="help-modal-header">
                    <h2 class="help-modal-title">
                        <i class="fas fa-question-circle"></i>
                        Need Help?
                    </h2>
                    <button class="help-modal-close" onclick="closeHelpModal()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="help-modal-body">
                    <div class="help-section">
                        <h3><i class="fas fa-headset"></i> Contact Support</h3>
                        <div class="help-options">
                            <div class="help-option">
                                <i class="fas fa-envelope"></i>
                                <div>
                                    <strong>Email Support</strong>
                                    <p>support@secureauth.com</p>
                                </div>
                            </div>
                            <div class="help-option">
                                <i class="fas fa-phone"></i>
                                <div>
                                    <strong>Phone Support</strong>
                                    <p>+1 (555) 123-4567</p>
                                </div>
                            </div>
                            <div class="help-option">
                                <i class="fas fa-clock"></i>
                                <div>
                                    <strong>Support Hours</strong>
                                    <p>Monday - Friday: 8:00 AM - 6:00 PM EST</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="help-section">
                        <h3><i class="fas fa-book"></i> Documentation & Resources</h3>
                        <div class="help-links">
                            <a href="#" class="help-link" onclick="showToast('Documentation', 'User guide and documentation coming soon!', 'info')">
                                <i class="fas fa-file-alt"></i>
                                User Guide
                            </a>
                            <a href="#" class="help-link" onclick="showToast('FAQ', 'Frequently Asked Questions coming soon!', 'info')">
                                <i class="fas fa-question"></i>
                                FAQ
                            </a>
                            <a href="#" class="help-link" onclick="showToast('Tutorials', 'Video tutorials coming soon!', 'info')">
                                <i class="fas fa-play-circle"></i>
                                Video Tutorials
                            </a>
                        </div>
                    </div>
                    
                    <div class="help-section">
                        <h3><i class="fas fa-tools"></i> Quick Actions</h3>
                        <div class="help-actions">
                            <button class="help-action-btn" onclick="showPasswordResetHelp()">
                                <i class="fas fa-key"></i>
                                Reset Password
                            </button>
                            <button class="help-action-btn" onclick="showMFAHelp()">
                                <i class="fas fa-shield-alt"></i>
                                MFA Setup
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Add smooth animation
    const modal = document.getElementById('helpModal');
    modal.style.opacity = '0';
    setTimeout(() => {
        modal.style.opacity = '1';
        modal.classList.add('show');
    }, 10);
    
    // Close modal when clicking outside
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            closeHelpModal();
        }
    });
    
    // Close modal with Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && modal) {
            closeHelpModal();
        }
    });
}

function closeHelpModal() {
    const modal = document.getElementById('helpModal');
    if (modal) {
        modal.classList.remove('show');
        modal.style.opacity = '0';
        setTimeout(() => {
            modal.remove();
        }, 300);
    }
}

function showPasswordResetHelp() {
    closeHelpModal();
    showToast('Password Reset', 'To reset your password, click "Forgot Password" on the login page or contact support for assistance.', 'info');
}

function showMFAHelp() {
    closeHelpModal();
    showToast('MFA Setup', 'Multi-Factor Authentication adds extra security. Go to your profile settings to set up MFA with your mobile device.', 'info');
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
