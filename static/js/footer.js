// Footer Modal Functionality
class FooterModal {
    constructor() {
        this.init();
    }

    init() {
        // Add click event listeners to footer links
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('footer-link')) {
                e.preventDefault();
                const linkText = e.target.textContent.trim();
                this.openModal(linkText);
            }
        });

        // Close modal when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('footer-modal')) {
                this.closeModal();
            }
        });

        // Close modal with escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }

    openModal(linkText) {
        // Remove existing modal if any
        const existingModal = document.getElementById('footerModal');
        if (existingModal) {
            existingModal.remove();
        }

        // Create modal content based on link text
        const content = this.getModalContent(linkText);
        
        // Create modal HTML
        const modalHTML = `
            <div id="footerModal" class="footer-modal" style="display: block;">
                <div class="footer-modal-content">
                    <div class="footer-modal-header">
                        <h2 class="footer-modal-title">${content.title}</h2>
                        <button class="footer-modal-close" onclick="footerModal.closeModal()">&times;</button>
                    </div>
                    <div class="footer-modal-body">
                        ${content.body}
                    </div>
                </div>
            </div>
        `;

        // Add modal to page
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        
        // Add smooth animation
        const modal = document.getElementById('footerModal');
        modal.style.opacity = '0';
        setTimeout(() => {
            modal.style.opacity = '1';
        }, 10);
    }

    closeModal() {
        const modal = document.getElementById('footerModal');
        if (modal) {
            modal.style.opacity = '0';
            setTimeout(() => {
                modal.remove();
            }, 300);
        }
    }

    getModalContent(linkText) {
        const content = {
            'Privacy Policy': {
                title: 'Privacy Policy',
                body: `
                    <p><strong>Last Updated:</strong> January 2025</p>
                    
                    <h3>Information We Collect</h3>
                    <p>We collect information you provide directly to us, such as when you create an account, use our services, or contact us for support.</p>
                    
                    <h3>How We Use Your Information</h3>
                    <ul>
                        <li>To provide, maintain, and improve our services</li>
                        <li>To process transactions and send related information</li>
                        <li>To send technical notices and support messages</li>
                        <li>To respond to your comments and questions</li>
                    </ul>
                    
                    <h3>Information Sharing</h3>
                    <p>We do not sell, trade, or otherwise transfer your personal information to third parties without your consent, except as described in this policy.</p>
                    
                    <h3>Data Security</h3>
                    <p>We implement appropriate security measures to protect your personal information against unauthorized access, alteration, disclosure, or destruction.</p>
                    
                    <h3>Contact Us</h3>
                    <p>If you have any questions about this Privacy Policy, please contact us at privacy@secureauth.com</p>
                `
            },
            'Terms of Service': {
                title: 'Terms of Service',
                body: `
                    <p><strong>Last Updated:</strong> January 2025</p>
                    
                    <h3>Acceptance of Terms</h3>
                    <p>By accessing and using SecureAuth services, you accept and agree to be bound by the terms and provision of this agreement.</p>
                    
                    <h3>Use License</h3>
                    <p>Permission is granted to temporarily use SecureAuth services for personal, non-commercial transitory viewing only. This is the grant of a license, not a transfer of title.</p>
                    
                    <h3>User Accounts</h3>
                    <ul>
                        <li>You are responsible for maintaining the confidentiality of your account</li>
                        <li>You are responsible for all activities that occur under your account</li>
                        <li>You must notify us immediately of any unauthorized use</li>
                    </ul>
                    
                    <h3>Prohibited Uses</h3>
                    <p>You may not use our services:</p>
                    <ul>
                        <li>For any unlawful purpose or to solicit others to perform unlawful acts</li>
                        <li>To violate any international, federal, provincial, or state regulations, rules, laws, or local ordinances</li>
                        <li>To infringe upon or violate our intellectual property rights or the intellectual property rights of others</li>
                    </ul>
                    
                    <h3>Service Availability</h3>
                    <p>We strive to maintain high service availability but do not guarantee uninterrupted access to our services.</p>
                    
                    <h3>Contact Information</h3>
                    <p>Questions about the Terms of Service should be sent to legal@secureauth.com</p>
                `
            },
            'Contact Support': {
                title: 'Contact Support',
                body: `
                    <p>We're here to help! Get in touch with our support team for assistance with your SecureAuth account.</p>
                    
                    <h3>Support Channels</h3>
                    <ul>
                        <li><strong>Email:</strong> support@secureauth.com</li>
                        <li><strong>Phone:</strong> +1 (555) 123-4567</li>
                        <li><strong>Hours:</strong> Monday - Friday, 9:00 AM - 6:00 PM EST</li>
                    </ul>
                    
                    <h3>Common Issues</h3>
                    <p><strong>Login Problems:</strong> Check your username and password. If you've forgotten your password, use the "Forgot Password" link on the login page.</p>
                    
                    <p><strong>MFA Issues:</strong> Ensure your authenticator app is properly configured. You can reset MFA settings in your account preferences.</p>
                    
                    <p><strong>Document Upload:</strong> Make sure your file is in a supported format (PDF, DOC, DOCX, JPG, PNG) and under 10MB in size.</p>
                    
                    <h3>Response Time</h3>
                    <p>We typically respond to support requests within 24 hours during business days. For urgent security issues, please call our support line directly.</p>
                    
                    <h3>Feedback</h3>
                    <p>We value your feedback! If you have suggestions for improving our service, please email us at feedback@secureauth.com</p>
                `
            }
        };

        return content[linkText] || {
            title: 'Information',
            body: '<p>This feature is coming soon. Please check back later.</p>'
        };
    }
}

// Initialize footer modal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.footerModal = new FooterModal();
});
