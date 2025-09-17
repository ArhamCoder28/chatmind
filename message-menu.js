document.addEventListener('DOMContentLoaded', function() {
    const messages = document.querySelectorAll('.message');
    const contextMenu = document.getElementById('contextMenu');
    let selectedMessage = null;

    // Add click event to each message
    messages.forEach(message => {
        message.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove previous selection
            messages.forEach(msg => msg.classList.remove('selected'));
            
            // Select current message
            this.classList.add('selected');
            selectedMessage = this;
            
            // Show context menu
            showContextMenu(e.pageX, e.pageY);
        });
    });

    // Context menu items click handlers
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', function() {
            const action = this.dataset.action;
            const messageId = selectedMessage?.dataset.messageId;
            const messageText = selectedMessage?.querySelector('.text')?.textContent;
            
            handleMenuAction(action, messageId, messageText);
            hideContextMenu();
        });
    });

    // Hide context menu when clicking outside
    document.addEventListener('click', function(e) {
        if (!contextMenu.contains(e.target) && !e.target.closest('.message')) {
            hideContextMenu();
        }
    });

    function showContextMenu(x, y) {
        contextMenu.style.left = x + 'px';
        contextMenu.style.top = y + 'px';
        contextMenu.classList.add('show');
    }

    function hideContextMenu() {
        contextMenu.classList.remove('show');
        messages.forEach(msg => msg.classList.remove('selected'));
        selectedMessage = null;
    }

    function handleMenuAction(action, messageId, messageText) {
        switch(action) {
            case 'reply':
                alert(`Reply to message ${messageId}: "${messageText}"`);
                break;
            case 'forward':
                alert(`Forward message ${messageId}: "${messageText}"`);
                break;
            case 'copy':
                navigator.clipboard.writeText(messageText);
                alert('Message copied to clipboard');
                break;
            case 'delete':
                if(confirm('Delete this message?')) {
                    selectedMessage.remove();
                }
                break;
            case 'edit':
                alert(`Edit message ${messageId}: "${messageText}"`);
                break;
        }
    }
});