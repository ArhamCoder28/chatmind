// Enhanced ChatMind Features JavaScript

class ChatMindEnhanced {
    constructor() {
        this.socket = io();
        this.currentTheme = 'light';
        this.mediaRecorder = null;
        this.audioChunks = [];
        this.init();
    }

    init() {
        this.loadTheme();
        this.setupSocketListeners();
        this.setupEventListeners();
        this.loadUserPreferences();
    }

    // Theme Management
    async loadTheme() {
        try {
            const response = await fetch('/user/theme');
            const data = await response.json();
            if (data.success) {
                this.setTheme(data.theme);
            }
        } catch (error) {
            console.error('Error loading theme:', error);
        }
    }

    setTheme(theme) {
        this.currentTheme = theme;
        document.body.className = theme === 'dark' ? 'dark-theme' : 'light-theme';
        localStorage.setItem('theme', theme);
    }

    async toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        try {
            const response = await fetch('/user/theme', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ theme: newTheme })
            });
            const data = await response.json();
            if (data.success) {
                this.setTheme(newTheme);
            }
        } catch (error) {
            console.error('Error updating theme:', error);
        }
    }

    // Voice Messages
    async startVoiceRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            this.mediaRecorder = new MediaRecorder(stream);
            this.audioChunks = [];

            this.mediaRecorder.ondataavailable = (event) => {
                this.audioChunks.push(event.data);
            };

            this.mediaRecorder.onstop = () => {
                const audioBlob = new Blob(this.audioChunks, { type: 'audio/wav' });
                this.processVoiceMessage(audioBlob);
            };

            this.mediaRecorder.start();
            this.showRecordingUI();
        } catch (error) {
            console.error('Error starting voice recording:', error);
            alert('Microphone access denied or not available');
        }
    }

    stopVoiceRecording() {
        if (this.mediaRecorder && this.mediaRecorder.state === 'recording') {
            this.mediaRecorder.stop();
            this.hideRecordingUI();
        }
    }

    async processVoiceMessage(audioBlob) {
        const reader = new FileReader();
        reader.onload = async () => {
            const audioData = reader.result;
            const duration = await this.getAudioDuration(audioBlob);
            
            try {
                const response = await fetch('/voice-message/upload', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        audio_data: audioData,
                        duration: duration,
                        receiver_id: this.getCurrentChatId()
                    })
                });
                const data = await response.json();
                if (data.success) {
                    this.displayVoiceMessage(data.message_id, audioData, duration);
                }
            } catch (error) {
                console.error('Error uploading voice message:', error);
            }
        };
        reader.readAsDataURL(audioBlob);
    }

    // Message Reactions
    async reactToMessage(messageId, reactionType) {
        try {
            const response = await fetch('/messages/react', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message_id: messageId,
                    reaction_type: reactionType
                })
            });
            const data = await response.json();
            if (data.success) {
                this.updateMessageReactions(messageId);
            }
        } catch (error) {
            console.error('Error reacting to message:', error);
        }
    }

    async loadMessageReactions(messageId) {
        try {
            const response = await fetch(`/messages/${messageId}/reactions`);
            const data = await response.json();
            if (data.success) {
                return data.reactions;
            }
        } catch (error) {
            console.error('Error loading reactions:', error);
        }
        return [];
    }

    // Message Threading
    async replyToMessage(replyToId, receiverId, content) {
        try {
            const response = await fetch('/messages/reply', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    reply_to_id: replyToId,
                    receiver_id: receiverId,
                    content: content
                })
            });
            const data = await response.json();
            if (data.success) {
                this.clearReplyUI();
                this.refreshMessages();
            }
        } catch (error) {
            console.error('Error sending reply:', error);
        }
    }

    // Message Forwarding
    async forwardMessage(messageId, receiverIds) {
        try {
            const response = await fetch('/messages/forward', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message_id: messageId,
                    receiver_ids: receiverIds
                })
            });
            const data = await response.json();
            if (data.success) {
                alert(data.message);
            }
        } catch (error) {
            console.error('Error forwarding message:', error);
        }
    }

    // Message Search
    async searchMessages(query) {
        try {
            const response = await fetch(`/messages/search?q=${encodeURIComponent(query)}`);
            const data = await response.json();
            if (data.success) {
                this.displaySearchResults(data.results);
            }
        } catch (error) {
            console.error('Error searching messages:', error);
        }
    }

    // Typing Indicators
    startTyping(chatId, chatType = 'user') {
        this.socket.emit('typing_start', { chat_id: chatId, chat_type: chatType });
    }

    stopTyping(chatId, chatType = 'user') {
        this.socket.emit('typing_stop', { chat_id: chatId, chat_type: chatType });
    }

    // Online Status
    async updateOnlineStatus(status) {
        try {
            const response = await fetch('/user/status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: status })
            });
            const data = await response.json();
            if (data.success) {
                this.updateStatusUI(status);
            }
        } catch (error) {
            console.error('Error updating status:', error);
        }
    }

    async getUserPresence(userId) {
        try {
            const response = await fetch(`/user/presence/${userId}`);
            const data = await response.json();
            if (data.success) {
                return data;
            }
        } catch (error) {
            console.error('Error getting user presence:', error);
        }
        return null;
    }

    // Message Templates
    async loadMessageTemplates() {
        try {
            const response = await fetch('/templates');
            const data = await response.json();
            if (data.success) {
                this.displayTemplates(data.templates);
            }
        } catch (error) {
            console.error('Error loading templates:', error);
        }
    }

    async saveMessageTemplate(name, content) {
        try {
            const response = await fetch('/templates', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, content: content })
            });
            const data = await response.json();
            if (data.success) {
                this.loadMessageTemplates();
            }
        } catch (error) {
            console.error('Error saving template:', error);
        }
    }

    // Scheduled Messages
    async scheduleMessage(receiverId, content, scheduledAt) {
        try {
            const response = await fetch('/messages/schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    receiver_id: receiverId,
                    content: content,
                    scheduled_at: scheduledAt
                })
            });
            const data = await response.json();
            if (data.success) {
                alert('Message scheduled successfully');
            }
        } catch (error) {
            console.error('Error scheduling message:', error);
        }
    }

    // Group Features
    async createGroupAnnouncement(groupId, content) {
        try {
            const response = await fetch(`/groups/${groupId}/announcements`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            const data = await response.json();
            if (data.success) {
                this.loadGroupAnnouncements(groupId);
            }
        } catch (error) {
            console.error('Error creating announcement:', error);
        }
    }

    async createGroupEvent(groupId, eventData) {
        try {
            const response = await fetch(`/groups/${groupId}/events`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            });
            const data = await response.json();
            if (data.success) {
                this.loadGroupEvents(groupId);
            }
        } catch (error) {
            console.error('Error creating event:', error);
        }
    }

    async createGroupPoll(groupId, pollData) {
        try {
            const response = await fetch(`/groups/${groupId}/polls`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(pollData)
            });
            const data = await response.json();
            if (data.success) {
                this.loadGroupPolls(groupId);
            }
        } catch (error) {
            console.error('Error creating poll:', error);
        }
    }

    async voteInPoll(pollId, optionIndex) {
        try {
            const response = await fetch(`/polls/${pollId}/vote`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ option_index: optionIndex })
            });
            const data = await response.json();
            if (data.success) {
                this.refreshPollResults(pollId);
            }
        } catch (error) {
            console.error('Error voting in poll:', error);
        }
    }

    // User Stories
    async postStory(content, mediaType = 'text', mediaUrl = null) {
        try {
            const response = await fetch('/stories', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: content,
                    media_type: mediaType,
                    media_url: mediaUrl
                })
            });
            const data = await response.json();
            if (data.success) {
                this.loadStories();
            }
        } catch (error) {
            console.error('Error posting story:', error);
        }
    }

    async loadStories() {
        try {
            const response = await fetch('/stories');
            const data = await response.json();
            if (data.success) {
                this.displayStories(data.stories);
            }
        } catch (error) {
            console.error('Error loading stories:', error);
        }
    }

    // Privacy & Notification Settings
    async updatePrivacySettings(settings) {
        try {
            const response = await fetch('/user/privacy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            const data = await response.json();
            if (data.success) {
                alert('Privacy settings updated');
            }
        } catch (error) {
            console.error('Error updating privacy settings:', error);
        }
    }

    async updateNotificationSettings(settings) {
        try {
            const response = await fetch('/user/notifications', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            const data = await response.json();
            if (data.success) {
                alert('Notification settings updated');
            }
        } catch (error) {
            console.error('Error updating notification settings:', error);
        }
    }

    // User Profile
    async updateUserProfile(profileData) {
        try {
            const response = await fetch('/user/profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(profileData)
            });
            const data = await response.json();
            if (data.success) {
                alert('Profile updated successfully');
            }
        } catch (error) {
            console.error('Error updating profile:', error);
        }
    }

    // Chat Export
    async exportChat(withUserId) {
        try {
            const response = await fetch(`/messages/export?with_user_id=${withUserId}`);
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'chat_export.txt';
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Error exporting chat:', error);
        }
    }

    // Socket Event Listeners
    setupSocketListeners() {
        this.socket.on('user_typing', (data) => {
            this.showTypingIndicator(data);
        });

        this.socket.on('new_message', (data) => {
            this.handleNewMessage(data);
        });

        this.socket.on('message_reaction', (data) => {
            this.updateMessageReactions(data.message_id);
        });
    }

    // UI Helper Methods
    setupEventListeners() {
        // Theme toggle button
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }

        // Voice message button
        const voiceBtn = document.getElementById('voice-message-btn');
        if (voiceBtn) {
            voiceBtn.addEventListener('mousedown', () => this.startVoiceRecording());
            voiceBtn.addEventListener('mouseup', () => this.stopVoiceRecording());
        }

        // Search input
        const searchInput = document.getElementById('message-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                if (e.target.value.length > 2) {
                    this.searchMessages(e.target.value);
                }
            });
        }

        // Typing indicators
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            let typingTimer;
            messageInput.addEventListener('input', () => {
                this.startTyping(this.getCurrentChatId());
                clearTimeout(typingTimer);
                typingTimer = setTimeout(() => {
                    this.stopTyping(this.getCurrentChatId());
                }, 1000);
            });
        }
    }

    // Utility Methods
    getCurrentChatId() {
        // Implementation depends on your chat UI structure
        return document.querySelector('.active-chat')?.dataset.userId || null;
    }

    getAudioDuration(audioBlob) {
        return new Promise((resolve) => {
            const audio = new Audio();
            audio.onloadedmetadata = () => {
                resolve(audio.duration);
            };
            audio.src = URL.createObjectURL(audioBlob);
        });
    }

    showRecordingUI() {
        const recordingIndicator = document.getElementById('recording-indicator');
        if (recordingIndicator) {
            recordingIndicator.style.display = 'block';
        }
    }

    hideRecordingUI() {
        const recordingIndicator = document.getElementById('recording-indicator');
        if (recordingIndicator) {
            recordingIndicator.style.display = 'none';
        }
    }

    displayVoiceMessage(messageId, audioData, duration) {
        // Implementation for displaying voice message in chat
        console.log('Voice message uploaded:', messageId);
    }

    updateMessageReactions(messageId) {
        // Implementation for updating reaction display
        this.loadMessageReactions(messageId).then(reactions => {
            // Update UI with reactions
        });
    }

    clearReplyUI() {
        const replyContainer = document.getElementById('reply-container');
        if (replyContainer) {
            replyContainer.style.display = 'none';
        }
    }

    refreshMessages() {
        // Implementation for refreshing message list
        console.log('Refreshing messages...');
    }

    displaySearchResults(results) {
        const searchResults = document.getElementById('search-results');
        if (searchResults) {
            searchResults.innerHTML = results.map(result => 
                `<div class="search-result" data-message-id="${result.id}">
                    <strong>${result.sender_name}</strong>: ${result.content}
                    <small>${result.created_at}</small>
                </div>`
            ).join('');
        }
    }

    showTypingIndicator(data) {
        if (data.is_typing) {
            const indicator = document.getElementById(`typing-${data.user_id}`);
            if (indicator) {
                indicator.style.display = 'block';
            }
        } else {
            const indicator = document.getElementById(`typing-${data.user_id}`);
            if (indicator) {
                indicator.style.display = 'none';
            }
        }
    }

    updateStatusUI(status) {
        const statusIndicator = document.getElementById('user-status');
        if (statusIndicator) {
            statusIndicator.className = `status-${status}`;
            statusIndicator.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }
    }

    displayTemplates(templates) {
        const templatesList = document.getElementById('templates-list');
        if (templatesList) {
            templatesList.innerHTML = templates.map(template =>
                `<div class="template-item" data-template-id="${template.id}">
                    <h4>${template.name}</h4>
                    <p>${template.content}</p>
                    <button onclick="chatMind.useTemplate('${template.content}')">Use</button>
                </div>`
            ).join('');
        }
    }

    useTemplate(content) {
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.value = content;
        }
    }

    displayStories(stories) {
        const storiesContainer = document.getElementById('stories-container');
        if (storiesContainer) {
            storiesContainer.innerHTML = stories.map(story =>
                `<div class="story-item" data-story-id="${story.id}">
                    <div class="story-author">${story.username}</div>
                    <div class="story-content">${story.content}</div>
                    <div class="story-time">${story.created_at}</div>
                </div>`
            ).join('');
        }
    }

    handleNewMessage(data) {
        // Handle incoming messages with enhanced features
        console.log('New message received:', data);
    }

    loadUserPreferences() {
        // Load user preferences on initialization
        this.loadMessageTemplates();
        this.loadStories();
    }

    refreshPollResults(pollId) {
        // Refresh poll results after voting
        console.log('Refreshing poll results for:', pollId);
    }

    loadGroupAnnouncements(groupId) {
        // Load group announcements
        fetch(`/groups/${groupId}/announcements`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Display announcements
                }
            });
    }

    loadGroupEvents(groupId) {
        // Load group events
        fetch(`/groups/${groupId}/events`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Display events
                }
            });
    }

    loadGroupPolls(groupId) {
        // Load group polls
        fetch(`/groups/${groupId}/polls`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Display polls
                }
            });
    }
}

// Initialize enhanced features when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.chatMind = new ChatMindEnhanced();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ChatMindEnhanced;
}