document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const submitBtn = document.getElementById('submitBtn');

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const username = this.username.value.trim();
            const password = this.password.value;

            if (!username || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
                return;
            }

            if (username.length < 3) {
                e.preventDefault();
                alert('Username must be at least 3 characters long');
                return;
            }
        });
    }

    if (registerForm && passwordInput) {
        function validatePassword(password) {
            const requirements = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
            };
            
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(req);
                if (element) {
                    element.className = requirements[req] ? 'valid' : 'invalid';
                }
            });
            
            return Object.values(requirements).every(Boolean);
        }

        function checkPasswordMatch() {
            const matchDiv = document.getElementById('passwordMatch');
            if (confirmPasswordInput.value && passwordInput.value) {
                const match = passwordInput.value === confirmPasswordInput.value;
                matchDiv.textContent = match ? 'Passwords match' : 'Passwords do not match';
                matchDiv.className = match ? 'match' : 'no-match';
                return match;
            }
            matchDiv.textContent = '';
            return false;
        }

        passwordInput.addEventListener('input', function() {
            validatePassword(this.value);
            if (confirmPasswordInput.value) checkPasswordMatch();
        });

        confirmPasswordInput.addEventListener('input', checkPasswordMatch);

        registerForm.addEventListener('submit', function(e) {
            const username = this.username.value.trim();
            const email = this.email.value.trim();
            const password = this.password.value;
            const confirmPassword = this.confirm_password.value;

            if (!username || !email || !password || !confirmPassword) {
                e.preventDefault();
                alert('Please fill in all fields');
                return;
            }

            if (!validatePassword(password)) {
                e.preventDefault();
                alert('Password does not meet security requirements');
                return;
            }

            if (password !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match');
                return;
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                e.preventDefault();
                alert('Please enter a valid email address');
                return;
            }
        });
    }
});