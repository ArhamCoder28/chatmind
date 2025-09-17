// Message Management Functions for Chat System

class MessageManager {
    constructor() {
        this.socket = io();
        this.setupSocketListeners();
    }

    setupSocketListeners() {
        // Listen for message deleted for everyone
        this.socket.on('message_deleted_for_everyone', (data) => {
            this.removeMessageFromUI(data.message_id);
            this.showNotification(`Message deleted by ${data.deleted_by === getCurrentUserId() ? 'you' : 'sender'}`);
        });

        // Listen for group message deleted for everyone
        this.socket.on('group_message_deleted_for_everyone', (data) => {
            this.removeGroupMessageFromUI(data.message_id, data.group_id);
            this.showNotification(`Group message deleted by ${data.deleted_by === getCurrentUserId() ? 'you' : 'sender'}`);
        });
    }

    // Delete message for everyone (only sender can do this)
    async deleteMessageForEveryone(messageId) {
        try {
            const response = await fetch('/messages/delete-for-everyone', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message_id: messageId })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Message deleted for everyone');
                return true;
            } else {
                this.showError(result.message);
                return false;
            }
        } catch (error) {
            this.showError('Failed to delete message');
            return false;
        }
    }

    // Delete message for current user only
    async deleteMessageForMe(messageId) {
        try {
            const response = await fetch('/messages/delete-for-me', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message_id: messageId })
            });

            const result = await response.json();
            
            if (result.success) {
                this.removeMessageFromUI(messageId);
                this.showNotification('Message deleted for you');
                return true;
            } else {
                this.showError(result.message);
                return false;
            }
        } catch (error) {
            this.showError('Failed to delete message');
            return false;
        }
    }

    // Delete group message for everyone (only sender can do this)
    async deleteGroupMessageForEveryone(messageId) {
        try {
            const response = await fetch('/groups/messages/delete-for-everyone', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message_id: messageId })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Group message deleted for everyone');
                return true;
            } else {
                this.showError(result.message);
                return false;
            }
        } catch (error) {
            this.showError('Failed to delete group message');
            return false;
        }
    }

    // Show message options menu
    showMessageOptions(messageElement, messageId, senderId, isGroupMessage = false) {
        const currentUserId = getCurrentUserId();
        const isSender = senderId === currentUserId;

        // Remove existing menu
        this.hideMessageOptions();

        const menu = document.createElement('div');
        menu.className = 'message-options-menu';
        menu.innerHTML = `
            <div class="message-option" onclick="messageManager.deleteMessageForMe(${messageId})">
                <i class="fas fa-trash"></i> Delete for me
            </div>
            ${isSender ? `
                <div class="message-option delete-for-everyone" onclick="messageManager.${isGroupMessage ? 'deleteGroupMessageForEveryone' : 'deleteMessageForEveryone'}(${messageId})">
                    <i class="fas fa-trash-alt"></i> Delete for everyone
                </div>
            ` : ''}
        `;

        // Position menu near the message
        const rect = messageElement.getBoundingClientRect();
        menu.style.position = 'fixed';
        menu.style.top = rect.top + 'px';
        menu.style.left = (rect.right - 150) + 'px';
        menu.style.zIndex = '1000';

        document.body.appendChild(menu);

        // Close menu when clicking outside
        setTimeout(() => {
            document.addEventListener('click', this.hideMessageOptions.bind(this), { once: true });
        }, 100);
    }

    hideMessageOptions() {
        const existingMenu = document.querySelector('.message-options-menu');
        if (existingMenu) {
            existingMenu.remove();
        }
    }

    // Remove message from UI
    removeMessageFromUI(messageId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (messageElement) {
            messageElement.remove();
        }
    }

    // Remove group message from UI
    removeGroupMessageFromUI(messageId, groupId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"][data-group-id="${groupId}"]`);
        if (messageElement) {
            messageElement.remove();
        }
    }

    // Show notification
    showNotification(message) {
        // Create or update notification element
        let notification = document.getElementById('message-notification');
        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'message-notification';
            notification.className = 'notification success';
            document.body.appendChild(notification);
        }
        
        notification.textContent = message;
        notification.className = 'notification success show';
        
        setTimeout(() => {
            notification.className = 'notification success';
        }, 3000);
    }

    // Show error message
    showError(message) {
        let notification = document.getElementById('message-notification');
        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'message-notification';
            notification.className = 'notification error';
            document.body.appendChild(notification);
        }
        
        notification.textContent = message;
        notification.className = 'notification error show';
        
        setTimeout(() => {
            notification.className = 'notification error';
        }, 3000);
    }
}

// Helper function to get current user ID (implement based on your session management)
function getCurrentUserId() {
    // This should return the current user's ID from your session or global variable
    return window.currentUserId || sessionStorage.getItem('userId');
}

// Initialize message manager
const messageManager = new MessageManager();

// Add context menu to messages (call this when rendering messages)
function addMessageContextMenu(messageElement, messageId, senderId, isGroupMessage = false) {
    messageElement.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        messageManager.showMessageOptions(messageElement, messageId, senderId, isGroupMessage);
    });

    // Also add a delete button for mobile/touch devices
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'message-delete-btn';
    deleteBtn.innerHTML = '<i class="fas fa-ellipsis-v"></i>';
    deleteBtn.onclick = (e) => {
        e.stopPropagation();
        messageManager.showMessageOptions(messageElement, messageId, senderId, isGroupMessage);
    };
    
    messageElement.appendChild(deleteBtn);
}

// Example usage in your message rendering function:
/*
function renderMessage(message) {
    const messageElement = document.createElement('div');
    messageElement.className = 'message';
    messageElement.setAttribute('data-message-id', message.id);
    if (message.group_id) {
        messageElement.setAttribute('data-group-id', message.group_id);
    }
    
    messageElement.innerHTML = `
        <div class="message-content">${message.content}</div>
        <div class="message-time">${formatTime(message.created_at)}</div>
    `;
    
    // Add context menu functionality
    addMessageContextMenu(messageElement, message.id, message.sender_id, !!message.group_id);
    
    return messageElement;
}
*/