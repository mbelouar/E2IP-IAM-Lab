// Main JavaScript file for the authentication system

document.addEventListener('DOMContentLoaded', function() {
    // Enhanced header interactions
    const mainHeader = document.querySelector('.main-header');
    const brandLogo = document.querySelector('.brand .logo');
    
    if (mainHeader && brandLogo) {
        // Set active nav item based on current URL
        const currentPath = window.location.pathname;
        const navItems = document.querySelectorAll('.nav-button');
        
        navItems.forEach(item => {
            const href = item.getAttribute('href');
            if (href === currentPath || 
                (currentPath.includes('/login') && href.includes('/login')) ||
                (currentPath === '/' && href === '/')) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
    }
    
    // Enhance enterprise login button interaction
    const enterpriseBtn = document.querySelector('.enterprise-btn.adfs');
    if (enterpriseBtn) {
        // Add subtle pulse effect when hovering near the button
        enterpriseBtn.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left; // x position within the element
            const y = e.clientY - rect.top;  // y position within the element
            
            // Calculate distance from center
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            // Apply subtle transform based on mouse position
            const offsetX = (x - centerX) / 20;
            const offsetY = (y - centerY) / 20;
            
            this.style.transform = `perspective(800px) translate3d(${offsetX}px, ${offsetY}px, 0) scale(1.01)`;
        });
        
        // Reset transform on mouse leave
        enterpriseBtn.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    }
    
    // Handle message dismissal with improved UI
    const messages = document.querySelectorAll('.message');
    
    if (messages.length > 0) {
        messages.forEach(message => {
            // Add close button to each message
            const closeBtn = document.createElement('span');
            closeBtn.innerHTML = '<i class="fas fa-times"></i>';
            closeBtn.classList.add('close-btn');
            closeBtn.style.float = 'right';
            closeBtn.style.cursor = 'pointer';
            closeBtn.style.marginLeft = '10px';
            message.appendChild(closeBtn);
            
            // Add click event to close button with animation
            closeBtn.addEventListener('click', function() {
                message.style.opacity = '0';
                message.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            });
            
            // Auto dismiss messages after 5 seconds
            setTimeout(() => {
                message.style.opacity = '0';
                message.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            }, 5000);
        });
    }
    
    // Enhanced ADFS Login Page animations
    const authContainer = document.querySelector('.auth-container');
    const enterpriseBtn = document.querySelector('.enterprise-btn.adfs');
    const logoBadges = document.querySelectorAll('.logo-badge');
    
    // Function to add animation with delay
    function animateWithDelay(element, className, delay) {
        if (element) {
            setTimeout(() => {
                element.classList.add(className);
            }, delay);
        }
    }
    
    // Add improved hover effect to enterprise button
    if (enterpriseBtn) {
        // Add subtle transform effect on mouse hover
        enterpriseBtn.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left; // x position within the element
            const y = e.clientY - rect.top;  // y position within the element
            
            // Calculate distance from center
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            // Apply subtle transform based on mouse position
            const offsetX = (x - centerX) / 20;
            const offsetY = (y - centerY) / 20;
            
            this.style.transform = `perspective(800px) translate3d(${offsetX}px, ${offsetY}px, 0) scale(1.01)`;
        });
        
        // Reset transform on mouse leave
        enterpriseBtn.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    }
    
    // Check if we're on the login page
    if (authContainer && enterpriseBtn) {
        // Add entrance animations to elements
        authContainer.style.opacity = '0';
        authContainer.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            authContainer.style.transition = 'all 0.6s ease';
            authContainer.style.opacity = '1';
            authContainer.style.transform = 'translateY(0)';
        }, 300);
        
        // Animate the ADFS button with a delay
        setTimeout(() => {
            enterpriseBtn.classList.add('animated');
        }, 1000);
        
        // Enhanced header animations
        const authHeader = document.querySelector('.auth-header');
        const companyName = document.querySelector('.company-name');
        const decorationLines = document.querySelectorAll('.decoration-line');
        
        if (authHeader && companyName) {
            // Add a subtle text shadow to company name
            setTimeout(() => {
                companyName.style.transition = 'text-shadow 0.5s ease';
                companyName.style.textShadow = '0 0 10px rgba(229, 9, 20, 0.3)';
                
                // Animate decoration lines
                if (decorationLines.length) {
                    decorationLines.forEach((line, index) => {
                        setTimeout(() => {
                            line.style.transition = 'width 1s ease';
                            line.style.width = '80px';
                        }, 1200 + (index * 200));
                    });
                }
            }, 800);
        }
        
        // Animate the logo badges sequentially
        if (logoBadges.length > 0) {
            logoBadges.forEach((badge, index) => {
                badge.style.opacity = '0';
                badge.style.transform = 'translateY(15px)';
                
                setTimeout(() => {
                    badge.style.transition = 'all 0.5s ease';
                    badge.style.opacity = '1';
                    badge.style.transform = 'translateY(0)';
                }, 1500 + (index * 200));
            });
        }
        
        // Add hover effect to auth container
        authContainer.addEventListener('mousemove', function(e) {
            const xPos = (e.clientX / window.innerWidth) - 0.5;
            const yPos = (e.clientY / window.innerHeight) - 0.5;
            
            authContainer.style.transform = `perspective(1000px) rotateY(${xPos * 2}deg) rotateX(${yPos * -2}deg)`;
        });
        
        authContainer.addEventListener('mouseleave', function() {
            authContainer.style.transform = 'perspective(1000px) rotateY(0deg) rotateX(0deg)';
        });
    }
    
    // Enhanced form validation and password visibility toggle
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        const passwordFields = form.querySelectorAll('input[type="password"]');
        
        passwordFields.forEach(field => {
            // Create password toggle button with icon
            const toggleBtn = document.createElement('button');
            toggleBtn.type = 'button';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
            toggleBtn.classList.add('password-toggle');
            toggleBtn.style.position = 'absolute';
            toggleBtn.style.right = '10px';
            toggleBtn.style.top = '50%';
            toggleBtn.style.transform = 'translateY(-50%)';
            toggleBtn.style.background = 'none';
            toggleBtn.style.border = 'none';
            toggleBtn.style.color = '#777';
            toggleBtn.style.cursor = 'pointer';
            toggleBtn.style.zIndex = '10';
            toggleBtn.style.padding = '5px';
            
            // Create a wrapper for the password field
            const wrapper = document.createElement('div');
            wrapper.style.position = 'relative';
            
            // Replace the password field with the wrapper containing the field and button
            field.parentNode.insertBefore(wrapper, field);
            wrapper.appendChild(field);
            wrapper.appendChild(toggleBtn);
            
            // Add click event to toggle button with improved UI
            toggleBtn.addEventListener('click', function() {
                if (field.type === 'password') {
                    field.type = 'text';
                    toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
                } else {
                    field.type = 'password';
                    toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
                }
                
                // Add small animation
                field.style.transition = 'all 0.3s ease';
                field.style.borderColor = 'var(--primary-color)';
                setTimeout(() => {
                    field.style.borderColor = '';
                }, 300);
            });
        });
        
        // Real-time form validation
        const inputs = form.querySelectorAll('input:not([type="checkbox"])');
        inputs.forEach(input => {
            input.addEventListener('blur', function() {
                if (input.value.trim() === '') {
                    input.style.borderColor = 'var(--error-color)';
                    
                    // Check if error message already exists
                    let errorMessage = input.nextElementSibling;
                    if (!errorMessage || !errorMessage.classList.contains('field-error')) {
                        errorMessage = document.createElement('div');
                        errorMessage.classList.add('field-error');
                        errorMessage.style.color = 'var(--error-color)';
                        errorMessage.style.fontSize = '0.8rem';
                        errorMessage.style.marginTop = '0.3rem';
                        input.parentNode.insertBefore(errorMessage, input.nextSibling);
                    }
                    
                    errorMessage.textContent = 'This field is required';
                } else {
                    input.style.borderColor = 'var(--success-color)';
                    
                    // Remove error message if it exists
                    const errorMessage = input.nextElementSibling;
                    if (errorMessage && errorMessage.classList.contains('field-error')) {
                        errorMessage.remove();
                    }
                }
            });
            
            input.addEventListener('input', function() {
                input.style.borderColor = '';
                
                // Remove error message if it exists
                const errorMessage = input.nextElementSibling;
                if (errorMessage && errorMessage.classList.contains('field-error')) {
                    errorMessage.remove();
                }
            });
        });
    });
    
    // Enhanced animation effect for cards
    const cards = document.querySelectorAll('.card');
    
    if (cards.length > 0) {
        // Initially set cards to be slightly transparent
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(30px)';
            
            // Animate cards into view with a stagger effect
            setTimeout(() => {
                card.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, 150 * index);
        });
    }
    
    // Add interactivity to dashboard elements
    const securityScore = document.querySelector('.score-circle');
    if (securityScore) {
        securityScore.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1)';
            this.style.transition = 'transform 0.3s ease';
        });
        
        securityScore.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    }
    
    // Add subtle hover effects to actionable elements
    const actionButtons = document.querySelectorAll('.action-button, .btn-primary, .social-btn');
    actionButtons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-3px)';
            this.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.1)';
            this.style.transition = 'all 0.3s ease';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
        });
    });
    
    // Registration validation code removed - no longer needed
});
