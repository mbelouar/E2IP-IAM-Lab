// Enhanced login card animations
document.addEventListener('DOMContentLoaded', function() {
    // Add active class to the buttons
    const standardBtn = document.getElementById('standardLoginBtn');
    const ssoBtn = document.getElementById('ssoLoginBtn');
    
    // Make sure buttons are initialized with active class
    if (standardBtn && ssoBtn) {
        // Default to SSO login option as specified
        ssoBtn.classList.add('active');
        
        standardBtn.addEventListener('click', function() {
            standardBtn.classList.add('active');
            ssoBtn.classList.remove('active');
        });
        
        ssoBtn.addEventListener('click', function() {
            ssoBtn.classList.add('active');
            standardBtn.classList.remove('active');
        });
    }
    
    // Enhance form transitions
    enhanceFormTransitions();
    
    // Add ripple effect to buttons
    addRippleEffect();
    
    // Add subtle parallax effect to login card
    addParallaxEffect();
    
    // Create enhanced background elements
    enhanceBackgroundElements();
});

// Enhanced form transitions
function enhanceFormTransitions() {
    const standardForm = document.getElementById('standardLoginForm');
    const ssoForm = document.getElementById('ssoLoginForm');
    
    if (standardForm && ssoForm) {
        // Ensure initial state is properly set with display:none to allow animation
        standardForm.style.opacity = '0';
        ssoForm.style.opacity = '0';
        
        // Default to SSO as specified
        setTimeout(() => {
            ssoForm.style.display = 'block';
            ssoForm.style.opacity = '1';
        }, 100);
    }
}

// Original toggleLoginForm function enhancement with improved animations
window.toggleLoginForm = function(loginType) {
    const standardForm = document.getElementById('standardLoginForm');
    const ssoForm = document.getElementById('ssoLoginForm');
    const standardBtn = document.getElementById('standardLoginBtn');
    const ssoBtn = document.getElementById('ssoLoginBtn');
    
    // Prevent repeated clicks during animation
    if (standardForm.classList.contains('animating') || ssoForm.classList.contains('animating')) {
        return;
    }
    
    if (loginType === 'standard') {
        // Already showing this form
        if (standardForm.style.display === 'block') return;
        
        // Mark as animating
        standardForm.classList.add('animating');
        ssoForm.classList.add('animating');
        
        // Fade out SSO form with class for smoother animation
        ssoForm.classList.add('fade-out');
        
        setTimeout(() => {
            ssoForm.style.display = 'none';
            standardForm.style.display = 'block';
            
            // Small delay to trigger animation
            setTimeout(() => {
                standardForm.style.opacity = '1';
                standardForm.classList.remove('fade-out');
                
                // Remove animating class after animation completes
                setTimeout(() => {
                    standardForm.classList.remove('animating');
                    ssoForm.classList.remove('animating');
                }, 300);
            }, 50);
        }, 200);
        
        // Update active states with a nice transition
        standardBtn.classList.add('active');
        ssoBtn.classList.remove('active');
        
        // Show a subtle toast notification
        setTimeout(() => {
            showToast('Standard Login', 'Enter your company username and password', 'info');
        }, 300);
    } else {
        // Already showing this form
        if (ssoForm.style.display === 'block') return;
        
        // Mark as animating
        standardForm.classList.add('animating');
        ssoForm.classList.add('animating');
        
        // Fade out standard form with class for smoother animation
        standardForm.classList.add('fade-out');
        
        setTimeout(() => {
            standardForm.style.display = 'none';
            ssoForm.style.display = 'block';
            
            // Small delay to trigger animation
            setTimeout(() => {
                ssoForm.style.opacity = '1';
                ssoForm.classList.remove('fade-out');
                
                // Remove animating class after animation completes
                setTimeout(() => {
                    standardForm.classList.remove('animating');
                    ssoForm.classList.remove('animating');
                }, 300);
            }, 50);
        }, 200);
        
        // Update active states
        standardBtn.classList.remove('active');
        ssoBtn.classList.add('active');
        
        // Show a subtle toast notification
        setTimeout(() => {
            showToast('SSO Login', 'Sign in using your organization\'s identity provider', 'info');
        }, 300);
    }
};

// Add ripple effect to buttons
function addRippleEffect() {
    const buttons = document.querySelectorAll('.auth-option-button, .login-button');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.classList.add('ripple');
            
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
}

// Add subtle parallax effect to login card
function addParallaxEffect() {
    const loginCard = document.querySelector('.login-card');
    const logo = document.querySelector('.logo');
    const securityFeatures = document.querySelectorAll('.security-item');
    
    // Only apply these effects on non-mobile devices
    if (window.innerWidth > 768) {
        if (loginCard) {
            document.addEventListener('mousemove', function(e) {
                // Calculate mouse position relative to viewport center
                const x = (e.clientX / window.innerWidth) - 0.5;
                const y = (e.clientY / window.innerHeight) - 0.5;
                
                // Very subtle movement for the login card (reduced from previous version)
                requestAnimationFrame(() => {
                    loginCard.style.transform = `perspective(1500px) rotateY(${x * 1}deg) rotateX(${y * -1}deg) translateZ(0)`;
                });
                
                // Move logo slightly more for a layered effect
                if (logo) {
                    requestAnimationFrame(() => {
                        logo.style.transform = `perspective(1000px) rotateY(${x * 3}deg) rotateX(${y * -3}deg) translateZ(10px)`;
                    });
                }
                
                // Subtle movement for security items
                securityFeatures.forEach((item, index) => {
                    const offsetFactor = (index + 1) * 0.2;
                    requestAnimationFrame(() => {
                        item.style.transform = `perspective(1000px) translateX(${x * 5 * offsetFactor}px) translateY(${y * 5 * offsetFactor}px)`;
                    });
                });
            });
            
            // Reset transforms when mouse leaves the container
            document.addEventListener('mouseleave', function() {
                requestAnimationFrame(() => {
                    loginCard.style.transform = `perspective(1000px) rotateY(0deg) rotateX(0deg) translateZ(0)`;
                    
                    if (logo) {
                        logo.style.transform = 'none';
                    }
                    
                    securityFeatures.forEach(item => {
                        item.style.transform = 'none';
                    });
                });
            });
        }
    }
}

// Add ripple style to the document
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
.ripple {
    position: absolute;
    background: rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    transform: scale(0);
    animation: rippleEffect 0.6s linear;
    pointer-events: none;
}

@keyframes rippleEffect {
    to {
        transform: scale(4);
        opacity: 0;
    }
}
`;
document.head.appendChild(rippleStyle);

// Create enhanced floating elements for background
function enhanceBackgroundElements() {
    const container = document.querySelector('.floating-elements');
    if (!container) return;
    
    // Clear existing elements
    container.innerHTML = '';
    
    // Create 6 floating elements instead of the original 4
    for (let i = 0; i < 6; i++) {
        const element = document.createElement('div');
        element.className = 'floating-element';
        container.appendChild(element);
    }
    
    // Add this function to the DOMContentLoaded event
    document.addEventListener('DOMContentLoaded', enhanceBackgroundElements);
