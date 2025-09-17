// FAQ Toggle
document.querySelectorAll('.faq-question').forEach(question => {
    question.addEventListener('click', () => {
        const answer = question.nextElementSibling;
        const isActive = question.classList.contains('active');
        
        // Close all other FAQs
        document.querySelectorAll('.faq-question').forEach(q => {
            q.classList.remove('active');
            q.nextElementSibling.classList.remove('active');
        });
        
        // Toggle current FAQ
        if (!isActive) {
            question.classList.add('active');
            answer.classList.add('active');
        }
    });
});

// Handle form submission with AJAX for better UX
document.getElementById('contactForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get form data
    const formData = new FormData(this);
    
    // Show loading state
    const statusElement = document.getElementById('statusMessage');
    statusElement.textContent = 'Sending your message...';
    statusElement.className = 'status-message status-loading';
    statusElement.style.display = 'block';
    
    try {
        // Send data to server using fetch API
        const response = await fetch('/contact', {
            method: 'POST',
            body: formData
        });
        
        if (response.redirected) {
            // If the server redirected, follow the redirect
            window.location.href = response.url;
        } else if (response.ok) {
            // Success message
            statusElement.textContent = 'Thank you! Your message has been sent successfully.';
            statusElement.className = 'status-message status-success';
            
            // Reset form
            this.reset();
        } else {
            // Error message
            statusElement.textContent = 'Error sending message. Please try again.';
            statusElement.className = 'status-message status-error';
        }
    } catch (error) {
        // Network error
        statusElement.textContent = 'Network error. Please check your connection and try again.';
        statusElement.className = 'status-message status-error';
        console.error('Error:', error);
    }
});

// Check for flash messages in the URL parameters
window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('message')) {
        const message = urlParams.get('message');
        const statusElement = document.getElementById('statusMessage');
        statusElement.textContent = message;
        statusElement.className = 'status-message status-success';
        statusElement.style.display = 'block';
        
        // Clean URL
        const url = new URL(window.location);
        url.searchParams.delete('message');
        window.history.replaceState({}, document.title, url);
    }
});