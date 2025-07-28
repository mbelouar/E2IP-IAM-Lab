// User Menu Toggle
function toggleUserMenu() {
    const userMenu = document.querySelector('.user-menu');
    const dropdown = document.getElementById('userDropdown');
    
    userMenu.classList.toggle('active');
    dropdown.classList.toggle('active');
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const userMenu = document.querySelector('.user-menu');
    const dropdown = document.getElementById('userDropdown');
    
    if (!userMenu.contains(event.target)) {
        userMenu.classList.remove('active');
        dropdown.classList.remove('active');
    }
});

// Service Card Interactions
document.addEventListener('DOMContentLoaded', function() {
    const serviceCards = document.querySelectorAll('.service-card');
    
    serviceCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-12px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
    
    // Add click handlers for service cards
    serviceCards.forEach(card => {
        card.addEventListener('click', function() {
            const service = this.dataset.service;
            handleServiceClick(service);
        });
    });
});

// Handle service card clicks
function handleServiceClick(service) {
    const serviceActions = {
        'sso': () => {
            console.log('Opening SSO Management Portal...');
            // Add your SSO portal logic here
            showNotification('Opening Enterprise SSO Portal...', 'info');
        },
        'mfa': () => {
            console.log('Opening MFA Configuration...');
            // Add your MFA configuration logic here
            showNotification('Opening MFA Security Center...', 'info');
        },
        'security': () => {
            console.log('Opening Security Command Center...');
            // Add your security center logic here
            showNotification('Opening Security Command Center...', 'info');
        },
        'organization': () => {
            console.log('Opening Organization Control Panel...');
            // Add your organization management logic here
            showNotification('Opening Executive Console...', 'info');
        },
        'intelligence': () => {
            console.log('Opening Intelligence Hub...');
            // Add your intelligence hub logic here
            showNotification('Opening Intelligence Hub...', 'info');
        },
        'infrastructure': () => {
            console.log('Opening Infrastructure Console...');
            // Add your infrastructure management logic here
            showNotification('Opening Infrastructure Console...', 'info');
        }
    };
    
    if (serviceActions[service]) {
        serviceActions[service]();
    }
}

// Notification System
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="closeNotification(this)">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add notification styles
    notification.style.cssText = `
        position: fixed;
        top: 2rem;
        right: 2rem;
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 1rem;
        padding: 1rem 1.5rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        min-width: 300px;
        transform: translateX(100%);
        transition: transform 0.3s ease;
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        closeNotification(notification.querySelector('.notification-close'));
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'info': 'info-circle',
        'success': 'check-circle',
        'warning': 'exclamation-triangle',
        'error': 'times-circle'
    };
    return icons[type] || 'info-circle';
}

function closeNotification(button) {
    const notification = button.closest('.notification');
    notification.style.transform = 'translateX(100%)';
    setTimeout(() => {
        notification.remove();
    }, 300);
}

// Activity Timeline Interactions
document.addEventListener('DOMContentLoaded', function() {
    const activityItems = document.querySelectorAll('.activity-item');
    
    activityItems.forEach(item => {
        const actionButton = item.querySelector('.activity-action');
        
        if (actionButton) {
            actionButton.addEventListener('click', function(e) {
                e.stopPropagation();
                showNotification('Opening detailed activity view...', 'info');
            });
        }
    });
});

// Real-time Updates Simulation
function simulateRealTimeUpdates() {
    // Update security score
    const securityScore = document.querySelector('.hero-stat-value');
    if (securityScore && securityScore.textContent === '99%') {
        // Simulate small fluctuations
        const scores = ['98%', '99%', '100%'];
        const randomScore = scores[Math.floor(Math.random() * scores.length)];
        securityScore.textContent = randomScore;
    }
    
    // Update system status indicators
    const statusIndicators = document.querySelectorAll('.status-indicator');
    statusIndicators.forEach(indicator => {
        if (indicator.classList.contains('active')) {
            // Add pulse animation
            indicator.style.animation = 'pulse 2s infinite';
        }
    });
}

// Initialize real-time updates
setInterval(simulateRealTimeUpdates, 30000); // Update every 30 seconds

// Smooth scrolling for internal links
document.addEventListener('DOMContentLoaded', function() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Enhanced hover effects for cards
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.service-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            // Add glow effect
            this.style.boxShadow = '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(59, 130, 246, 0.1)';
        });
        
        card.addEventListener('mouseleave', function() {
            // Remove glow effect
            this.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1)';
        });
    });
});

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('SecureAuth Executive Dashboard Initialized');
    
    // Add loading animation completion
    document.body.classList.add('loaded');
    
    // Initialize tooltips for badges
    const badges = document.querySelectorAll('.badge, .card-badge');
    badges.forEach(badge => {
        badge.title = badge.textContent;
    });
    
    // Add keyboard navigation
    document.addEventListener('keydown', function(e) {
        // ESC key closes dropdowns
        if (e.key === 'Escape') {
            const dropdown = document.getElementById('userDropdown');
            const userMenu = document.querySelector('.user-menu');
            
            if (dropdown.classList.contains('active')) {
                dropdown.classList.remove('active');
                userMenu.classList.remove('active');
            }
        }
    });
});

// Performance monitoring
function trackPerformance() {
    if ('performance' in window) {
        window.addEventListener('load', function() {
            const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
            console.log(`Dashboard loaded in ${loadTime}ms`);
        });
    }
}

trackPerformance();