document.addEventListener('DOMContentLoaded', function() {
    const loginToggle = document.getElementById('login-toggle');
    const registerToggle = document.getElementById('register-toggle');
    const otpToggle = document.getElementById('otp-toggle');
    
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const otpForm = document.getElementById('otpForm');
    
    function showForm(formToShow, activeToggle) {
        [loginForm, registerForm, otpForm].forEach(form => {
            if (form) form.classList.remove('active');
        });
        
        [loginToggle, registerToggle, otpToggle].forEach(toggle => {
            if (toggle) toggle.classList.remove('active');
        });
        
        if (formToShow) formToShow.classList.add('active');
        if (activeToggle) activeToggle.classList.add('active');
    }
    
    if (loginToggle) {
        loginToggle.addEventListener('click', () => showForm(loginForm, loginToggle));
    }
    
    if (registerToggle) {
        registerToggle.addEventListener('click', () => showForm(registerForm, registerToggle));
    }
    
    if (otpToggle) {
        otpToggle.addEventListener('click', () => showForm(otpForm, otpToggle));
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitBtn = registerForm.querySelector('.btn');
            const originalText = submitBtn.innerHTML;
            
            submitBtn.innerHTML = '<span class="loading"></span>Processing...';
            submitBtn.disabled = true;
            
            const formData = new FormData(registerForm);
            
            fetch('/register', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.requires_otp) {
                    showForm(otpForm, otpToggle);
                    otpToggle.style.display = 'block';
                    
                    const emailInput = document.getElementById('email');
                    if (emailInput) {
                        sessionStorage.setItem('pendingEmail', emailInput.value);
                    }
                    
                    showMessage(data.message, 'success');
                } else if (data.success) {
                    showMessage(data.message, 'success');
                    setTimeout(() => window.location.href = '/dashboard', 1500);
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage('Registration failed. Please try again.', 'error');
            })
            .finally(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        });
    }
    
    if (otpForm) {
        otpForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitBtn = otpForm.querySelector('.btn');
            const originalText = submitBtn.innerHTML;
            const otpInput = document.getElementById('otp');
            const email = sessionStorage.getItem('pendingEmail');
            
            if (!email) {
                showMessage('Session expired. Please register again.', 'error');
                showForm(registerForm, registerToggle);
                return;
            }
            
            submitBtn.innerHTML = '<span class="loading"></span>Verifying...';
            submitBtn.disabled = true;
            
            fetch('/verify-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    otp: otpInput.value,
                    email: email
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage(data.message, 'success');
                    sessionStorage.removeItem('pendingEmail');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1500);
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage('Verification failed. Please try again.', 'error');
            })
            .finally(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        });
    }
    
    const resendOtpLink = document.getElementById('resend-otp');
    if (resendOtpLink) {
        resendOtpLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            const email = sessionStorage.getItem('pendingEmail');
            if (!email) {
                showMessage('Session expired. Please register again.', 'error');
                showForm(registerForm, registerToggle);
                return;
            }
            
            fetch('/resend-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message, data.success ? 'success' : 'error');
            })
            .catch(error => {
                showMessage('Failed to resend OTP. Please try again.', 'error');
            });
        });
    }
    
    function showMessage(message, type) {
        const existingMessages = document.querySelectorAll('.flash-message');
        existingMessages.forEach(msg => msg.remove());
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `flash-message ${type}`;
        messageDiv.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${message}`;
        
        const flashContainer = document.querySelector('.flash-messages');
        if (flashContainer) {
            flashContainer.appendChild(messageDiv);
            
            setTimeout(() => {
                messageDiv.style.opacity = '0';
                messageDiv.style.transform = 'translateY(-20px)';
                setTimeout(() => messageDiv.remove(), 300);
            }, 5000);
        }
    }
    
    showForm(loginForm, loginToggle);
});

function handleGoogleLogin() {
    window.location.href = '/auth/google';
}