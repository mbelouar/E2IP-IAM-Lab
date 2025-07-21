/**
 * Dashboard functionality for SecureAuth platform
 * Provides interactive elements and data visualization for the user dashboard
 */

// Dashboard state management
const DashboardState = {
    lastActivity: new Date(),
    activityTimer: null,
    securityScore: calculateSecurityScore(),
    notifications: []
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.dashboard-container')) {
        initializeActivityTracking();
        initializeCardAnimations();
        initializeSecurityStats();
        
        // Check for URL parameters that might indicate a return from authentication
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('login_success')) {
            showToast('Authentication Complete', 'You have successfully authenticated to the platform', 'success');
        }
        
        // Save session start time
        sessionStorage.setItem('sessionStart', new Date().toString());
    }
});

/**
 * Initialize activity tracking for security purposes
 */
function initializeActivityTracking() {
    // Update last activity time on user interaction
    ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
        document.addEventListener(event, () => {
            DashboardState.lastActivity = new Date();
        });
    });
    
    // Check user activity every minute
    DashboardState.activityTimer = setInterval(() => {
        const inactiveTime = (new Date() - DashboardState.lastActivity) / 1000 / 60; // in minutes
        
        // Warn after 14 minutes of inactivity
        if (inactiveTime >= 14) {
            showToast('Session Warning', 'Your session will expire in 1 minute due to inactivity', 'warning');
        }
        
        // Mock session timeout after 15 minutes
        if (inactiveTime >= 15) {
            showToast('Session Expired', 'Your session has expired due to inactivity', 'error');
            // In a real application, you would redirect to the login page here
            setTimeout(() => {
                window.location.href = '/login';
            }, 3000);
        }
    }, 60000); // Check every minute
}

/**
 * Add interactive animations to dashboard cards
 */
function initializeCardAnimations() {
    const cards = document.querySelectorAll('.dashboard-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-5px)';
            card.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.12)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = '';
            card.style.boxShadow = '';
        });
        
        // Add subtle pulse effect to success card
        if (card.classList.contains('success-card')) {
            const icon = card.querySelector('.success-icon');
            setInterval(() => {
                icon.classList.add('pulse');
                setTimeout(() => {
                    icon.classList.remove('pulse');
                }, 1000);
            }, 5000);
        }
    });
}

/**
 * Calculate a mock security score based on various factors
 */
function calculateSecurityScore() {
    // In a real application, this would be based on actual security factors
    // For this demo, we'll use a random score between 70-100
    return Math.floor(Math.random() * 30) + 70;
}

/**
 * Initialize and update security statistics on the dashboard
 */
function initializeSecurityStats() {
    const securityItems = document.querySelectorAll('.security-stat-item');
    
    securityItems.forEach(item => {
        // Add click handler to show more information
        item.addEventListener('click', () => {
            const label = item.querySelector('.stat-label').textContent;
            
            if (label === 'Password Strength') {
                showToast('Password Strength', 'Your password meets enterprise security requirements. It has a good mix of characters, length, and complexity.', 'info');
            } else if (label === 'MFA Status') {
                showToast('Multi-Factor Authentication', 'Your account is protected with multi-factor authentication. This adds an extra layer of security to your account.', 'info');
            } else if (label === 'Last Password Change') {
                showToast('Password Age', 'For optimal security, it is recommended to change your password every 30-45 days.', 'info');
            }
        });
    });
    
    // Add session timer
    const sessionStartTime = new Date(sessionStorage.getItem('sessionStart') || new Date().toString());
    
    setInterval(() => {
        const sessionDuration = Math.floor((new Date() - sessionStartTime) / 1000 / 60); // in minutes
        const sessionElement = document.querySelector('.session-info');
        
        if (sessionElement) {
            sessionElement.textContent = `Active session: ${sessionDuration} min`;
        }
    }, 60000); // Update every minute
}

/**
 * Show security recommendations
 */
function showSecurityRecommendations() {
    const recommendations = [
        {
            title: 'Enable MFA for all accounts',
            description: 'Multi-factor authentication significantly reduces the risk of unauthorized access.'
        },
        {
            title: 'Use a password manager',
            description: 'Password managers help you create and store strong, unique passwords for all your accounts.'
        },
        {
            title: 'Keep your software updated',
            description: 'Regular updates ensure you have the latest security patches.'
        }
    ];
    
    recommendations.forEach(rec => {
        showToast(rec.title, rec.description, 'info');
    });
}

/**
 * Show a simulated activity log
 */
function showActivityLog() {
    const logEntry = document.createElement('div');
    logEntry.className = 'activity-log-entry';
    logEntry.innerHTML = `
        <div class="log-timestamp">${new Date().toLocaleTimeString()}</div>
        <div class="log-action">User session active</div>
    `;
    
    const logContainer = document.querySelector('.activity-log');
    if (logContainer) {
        logContainer.appendChild(logEntry);
        
        // Keep only the last 5 entries
        const entries = logContainer.querySelectorAll('.activity-log-entry');
        if (entries.length > 5) {
            logContainer.removeChild(entries[0]);
        }
    }
}