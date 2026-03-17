// AI Chat functionality for ION
// Integrates Ollama LLM with the chat panel

// =============================================================================
// State
// =============================================================================

let aiChatActive = false;
let aiMessages = [];
let aiContextType = 'security';
let aiModel = null;
let aiAvailable = false;
let aiStreaming = false;

const AI_CONTEXTS = {
    security: { name: 'Security', icon: '🛡️', description: 'Cyber security expert' },
    engineering: { name: 'Engineering', icon: '🔧', description: 'Security engineering help' },
    coding: { name: 'Coding', icon: '💻', description: 'Security tooling & code' },
    general: { name: 'General', icon: '🤖', description: 'General assistance' },
};

const SIDEBAR_ROLE_TO_CONTEXT = {
    admin: 'security',
    analyst: 'security',
    senior_analyst: 'security',
    principal_analyst: 'security',
    lead: 'security',
    forensic: 'security',
    engineering: 'engineering',
};

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', function() {
    initAIChat();
});

async function initAIChat() {
    // Auto-select context based on user's role
    if (typeof currentUserData !== 'undefined' && currentUserData) {
        const role = currentUserData.focus_role || (currentUserData.roles && currentUserData.roles[0]) || 'analyst';
        aiContextType = SIDEBAR_ROLE_TO_CONTEXT[role] || 'security';
    }

    // Check AI availability
    await checkAIStatus();

    // Add AI tab to chat panel after it's created
    const checkPanel = setInterval(() => {
        const roomListView = document.getElementById('chat-room-list-view');
        if (roomListView) {
            clearInterval(checkPanel);
            addAITab();
            addAIChatView();
            // Sync the dropdown to match the auto-selected context
            const select = document.getElementById('ai-context-select');
            if (select) select.value = aiContextType;
        }
    }, 100);
}

async function checkAIStatus() {
    try {
        const response = await fetch('/api/ai/status', {
            credentials: 'include'
        });
        if (response.ok) {
            const data = await response.json();
            aiAvailable = data.available;
            aiModel = data.default_model;

            // Also update chat page model info if on that page
            const modelNameEl = document.querySelector('.ai-model-name');
            const modelStatusEl = document.getElementById('ai-model-status');
            if (modelNameEl && modelStatusEl) {
                if (data.available) {
                    modelNameEl.textContent = data.default_model || 'Unknown';
                    modelStatusEl.textContent = 'Online';
                    modelStatusEl.classList.remove('offline');
                } else {
                    modelNameEl.textContent = 'Not configured';
                    modelStatusEl.textContent = data.error || 'Offline';
                    modelStatusEl.classList.add('offline');
                }
            }
            return data;
        }
    } catch (error) {
        console.log('AI service not available:', error.message);
        aiAvailable = false;
    }
    return null;
}

// =============================================================================
// UI Components
// =============================================================================

function addAITab() {
    const roomList = document.getElementById('chat-room-list');
    if (!roomList) return;

    // Remove existing AI tab to avoid duplicates
    const existing = document.getElementById('ai-assistant-room');
    if (existing) existing.remove();

    // Add AI assistant as a special "room" at the top
    const aiRoom = document.createElement('div');
    aiRoom.id = 'ai-assistant-room';
    aiRoom.className = 'chat-room-item ai-room';
    aiRoom.onclick = () => openAIChat();
    aiRoom.innerHTML = `
        <div class="chat-room-avatar ai-avatar">
            <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                <circle cx="8" cy="14" r="2"/>
                <circle cx="16" cy="14" r="2"/>
            </svg>
        </div>
        <div class="chat-room-info">
            <div class="chat-room-name">AI Assistant</div>
            <div class="chat-room-preview">${aiAvailable ? 'Ask me anything...' : 'Not available'}</div>
        </div>
        <div class="chat-room-status ${aiAvailable ? 'online' : 'offline'}"></div>
    `;

    // Insert at the top of the room list
    roomList.insertBefore(aiRoom, roomList.firstChild);
}

function addAIChatView() {
    const panel = document.getElementById('chat-panel');
    if (!panel) return;

    // Don't duplicate
    if (document.getElementById('ai-chat-view')) return;

    const aiView = document.createElement('div');
    aiView.id = 'ai-chat-view';
    aiView.className = 'chat-active-view';
    aiView.innerHTML = `
        <div class="chat-room-header ai-header">
            <button class="chat-back-btn" onclick="closeAIChat()">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M15 18l-6-6 6-6"/>
                </svg>
            </button>
            <div class="chat-room-header-info">
                <div class="chat-room-header-name">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.5rem;">
                        <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                    </svg>
                    AI Assistant
                </div>
                <div class="chat-room-header-members">
                    <select id="ai-context-select" onchange="changeAIContext(this.value)" class="ai-context-select">
                        <option value="security">Security</option>
                        <option value="engineering">Engineering</option>
                        <option value="coding">Coding</option>
                        <option value="general">General</option>
                    </select>
                </div>
            </div>
            <button class="chat-header-btn" onclick="clearAIChat()" title="Clear chat">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                </svg>
            </button>
        </div>
        <div class="chat-messages ai-messages" id="ai-messages">
            <div class="ai-welcome">
                <div class="ai-welcome-icon">🤖</div>
                <h3>AI Assistant</h3>
                <p>I can help you with security analysis, coding questions, and more.</p>
                <div class="ai-quick-prompts">
                    <button onclick="sendAIQuickPrompt('Analyze this alert for potential threats')">Analyze alert</button>
                    <button onclick="sendAIQuickPrompt('Help me write a YARA rule')">Write YARA rule</button>
                    <button onclick="sendAIQuickPrompt('Explain this MITRE ATT&CK technique')">MITRE help</button>
                    <button onclick="sendAIQuickPrompt('Generate an Elasticsearch query')">ES query</button>
                </div>
            </div>
        </div>
        <div class="ai-typing-indicator" id="ai-typing-indicator" style="display: none;">
            <span></span><span></span><span></span>
            <span class="ai-typing-text">AI is thinking...</span>
        </div>
        <div class="chat-input-area">
            <div class="chat-input-wrapper">
                <textarea class="chat-input" id="ai-chat-input" placeholder="Ask the AI assistant..." rows="1"
                    onkeydown="handleAIInputKeydown(event)"
                    oninput="autoResizeTextarea(this)"></textarea>
                <button class="chat-send-btn" onclick="sendAIMessage()" id="ai-send-btn">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
                    </svg>
                </button>
            </div>
        </div>
    `;

    panel.appendChild(aiView);
}

// =============================================================================
// Chat Functions
// =============================================================================

function openAIChat() {
    if (!aiAvailable) {
        showNotification('AI service is not available. Please ensure Ollama is running.', 'error');
        return;
    }

    aiChatActive = true;

    // Clear inline styles and use classes for consistent toggling
    const listView = document.getElementById('chat-room-list-view');
    const activeView = document.getElementById('chat-active-view');
    const aiView = document.getElementById('ai-chat-view');

    if (listView) {
        listView.style.removeProperty('display');
        listView.classList.add('hidden');
    }
    if (activeView) {
        activeView.style.removeProperty('display');
        activeView.classList.remove('show');
    }
    if (aiView) {
        aiView.style.removeProperty('display');
        aiView.classList.add('show');
    }

    // Focus input
    setTimeout(() => {
        document.getElementById('ai-chat-input')?.focus();
    }, 100);
}

function closeAIChat() {
    aiChatActive = false;

    const listView = document.getElementById('chat-room-list-view');
    const aiView = document.getElementById('ai-chat-view');

    if (aiView) {
        aiView.classList.remove('show');
    }
    if (listView) {
        listView.classList.remove('hidden');
    }
}

function clearAIChat() {
    aiMessages = [];
    const messagesContainer = document.getElementById('ai-messages');
    messagesContainer.innerHTML = `
        <div class="ai-welcome">
            <div class="ai-welcome-icon">🤖</div>
            <h3>AI Assistant</h3>
            <p>I can help you with security analysis, coding questions, and more.</p>
            <div class="ai-quick-prompts">
                <button onclick="sendAIQuickPrompt('Analyze this alert for potential threats')">Analyze alert</button>
                <button onclick="sendAIQuickPrompt('Help me write a YARA rule')">Write YARA rule</button>
                <button onclick="sendAIQuickPrompt('Explain this MITRE ATT&CK technique')">MITRE help</button>
                <button onclick="sendAIQuickPrompt('Generate an Elasticsearch query')">ES query</button>
            </div>
        </div>
    `;
}

function changeAIContext(context) {
    aiContextType = context;
    showNotification(`Switched to ${AI_CONTEXTS[context].name} mode`, 'info');
}

function handleAIInputKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendAIMessage();
    }
}

function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 150) + 'px';
}

function sendAIQuickPrompt(prompt) {
    document.getElementById('ai-chat-input').value = prompt;
    sendAIMessage();
}

async function sendAIMessage() {
    const input = document.getElementById('ai-chat-input');
    const message = input.value.trim();

    if (!message || aiStreaming) return;

    // Clear input
    input.value = '';
    input.style.height = 'auto';

    // Remove welcome message if present
    const welcome = document.querySelector('.ai-welcome');
    if (welcome) welcome.remove();

    // Add user message to UI
    addAIMessageToUI('user', message);

    // Add to messages array
    aiMessages.push({ role: 'user', content: message });

    // Show typing indicator
    showAITyping(true);

    try {
        // Use streaming for better UX
        await streamAIResponse();
    } catch (error) {
        console.error('AI error:', error);
        addAIMessageToUI('error', 'Failed to get response: ' + error.message);
    } finally {
        showAITyping(false);
    }
}

async function streamAIResponse() {
    aiStreaming = true;

    const response = await fetch('/api/ai/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
            messages: aiMessages.map(m => ({ role: m.role, content: m.content })),
            context_type: aiContextType,
            stream: true,
        }),
    });

    if (!response.ok) {
        let msg = 'Request failed';
        try {
            const error = await response.json();
            msg = error.detail || msg;
        } catch {
            msg = `AI service error (${response.status})`;
        }
        throw new Error(msg);
    }

    // Create message element for streaming
    const messageDiv = addAIMessageToUI('assistant', '', true);
    const contentDiv = messageDiv.querySelector('.ai-message-content');

    let fullContent = '';
    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value);
            const lines = chunk.split('\n');

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.slice(6);
                    if (data === '[DONE]') continue;

                    try {
                        const parsed = JSON.parse(data);
                        if (parsed.error) {
                            throw new Error(parsed.error);
                        }
                        if (parsed.content) {
                            fullContent += parsed.content;
                            contentDiv.innerHTML = formatAIMessage(fullContent);
                            scrollAIMessages();
                        }
                    } catch (e) {
                        // Skip invalid JSON
                    }
                }
            }
        }
    } finally {
        aiStreaming = false;
    }

    // Add to messages array
    aiMessages.push({ role: 'assistant', content: fullContent });
}

function addAIMessageToUI(role, content, streaming = false) {
    const messagesContainer = document.getElementById('ai-messages');

    const messageDiv = document.createElement('div');
    messageDiv.className = `ai-message ${role}`;

    if (role === 'user') {
        messageDiv.innerHTML = `
            <div class="ai-message-avatar user-avatar">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                    <circle cx="12" cy="7" r="4"/>
                </svg>
            </div>
            <div class="ai-message-content">${escapeHtml(content)}</div>
        `;
    } else if (role === 'assistant') {
        messageDiv.innerHTML = `
            <div class="ai-message-avatar ai-avatar">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                </svg>
            </div>
            <div class="ai-message-content">${streaming ? '<span class="ai-cursor">▊</span>' : formatAIMessage(content)}</div>
            <div class="ai-message-actions">
                <button onclick="copyAIMessage(this)" title="Copy">
                    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2"/>
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                    </svg>
                </button>
            </div>
        `;
    } else if (role === 'error') {
        messageDiv.innerHTML = `
            <div class="ai-message-error">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M12 8v4M12 16h.01"/>
                </svg>
                ${escapeHtml(content)}
            </div>
        `;
    }

    messagesContainer.appendChild(messageDiv);
    scrollAIMessages();

    return messageDiv;
}

function formatAIMessage(content) {
    // Convert markdown-like formatting
    let formatted = escapeHtml(content);

    // Code blocks
    formatted = formatted.replace(/```(\w*)\n([\s\S]*?)```/g, (match, lang, code) => {
        return `<pre class="ai-code-block"><code class="language-${lang || 'text'}">${code.trim()}</code></pre>`;
    });

    // Inline code
    formatted = formatted.replace(/`([^`]+)`/g, '<code class="ai-inline-code">$1</code>');

    // Bold
    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Italic
    formatted = formatted.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Line breaks
    formatted = formatted.replace(/\n/g, '<br>');

    return formatted;
}

function scrollAIMessages() {
    const container = document.getElementById('ai-messages');
    container.scrollTop = container.scrollHeight;
}

function showAITyping(show) {
    const indicator = document.getElementById('ai-typing-indicator');
    indicator.style.display = show ? 'flex' : 'none';
}

function copyAIMessage(button) {
    const content = button.closest('.ai-message').querySelector('.ai-message-content');
    const text = content.innerText;

    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(message, type = 'info') {
    // Use existing notification system if available
    if (typeof showToast === 'function') {
        showToast(message, type);
    } else {
        console.log(`[${type}] ${message}`);
    }
}
