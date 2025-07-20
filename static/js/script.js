// Main JavaScript file for the authentication system

document.addEventListener('DOMContentLoaded', function() {
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
            
            // Auto-dismiss after 5 seconds with animation
            setTimeout(() => {
                message.style.opacity = '0';
                message.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            }, 5000);
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
