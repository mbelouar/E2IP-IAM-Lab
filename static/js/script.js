// Main JavaScript file for the authentication system

document.addEventListener('DOMContentLoaded', function() {
    // Handle message dismissal
    const messages = document.querySelectorAll('.message');
    
    if (messages.length > 0) {
        messages.forEach(message => {
            // Add close button to each message
            const closeBtn = document.createElement('span');
            closeBtn.innerHTML = '&times;';
            closeBtn.classList.add('close-btn');
            closeBtn.style.float = 'right';
            closeBtn.style.cursor = 'pointer';
            closeBtn.style.fontWeight = 'bold';
            message.prepend(closeBtn);
            
            // Add click event to close button
            closeBtn.addEventListener('click', function() {
                message.style.opacity = '0';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            });
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                message.style.opacity = '0';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            }, 5000);
        });
    }
    
    // Form validation enhancements
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        const passwordFields = form.querySelectorAll('input[type="password"]');
        
        passwordFields.forEach(field => {
            // Create password toggle button
            const toggleBtn = document.createElement('button');
            toggleBtn.type = 'button';
            toggleBtn.textContent = 'Show';
            toggleBtn.classList.add('password-toggle');
            toggleBtn.style.position = 'absolute';
            toggleBtn.style.right = '10px';
            toggleBtn.style.top = '50%';
            toggleBtn.style.transform = 'translateY(-50%)';
            toggleBtn.style.background = 'none';
            toggleBtn.style.border = 'none';
            toggleBtn.style.color = '#777';
            toggleBtn.style.cursor = 'pointer';
            
            // Create a wrapper for the password field
            const wrapper = document.createElement('div');
            wrapper.style.position = 'relative';
            
            // Replace the password field with the wrapper containing the field and button
            field.parentNode.insertBefore(wrapper, field);
            wrapper.appendChild(field);
            wrapper.appendChild(toggleBtn);
            
            // Add click event to toggle button
            toggleBtn.addEventListener('click', function() {
                if (field.type === 'password') {
                    field.type = 'text';
                    toggleBtn.textContent = 'Hide';
                } else {
                    field.type = 'password';
                    toggleBtn.textContent = 'Show';
                }
            });
        });
    });
    
    // Add animation effect to cards
    const cards = document.querySelectorAll('.card');
    
    if (cards.length > 0) {
        // Initially set cards to be slightly transparent
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            
            // Animate cards into view with a stagger effect
            setTimeout(() => {
                card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, 100 * index);
        });
    }
});
