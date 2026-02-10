// Chat functionality for IXION

// =============================================================================
// State
// =============================================================================

let chatOpen = false;
let activeRoomId = null;
let rooms = [];
let lastMessageTimestamp = null;
let pollInterval = null;
let typingTimeout = null;
let mentionUsers = [];
let selectedMentionIndex = 0;

const POLL_INTERVAL_MS = 5000;
const TYPING_TIMEOUT_MS = 3000;
const COMMON_EMOJIS = ['👍', '❤️', '😊', '🎉', '👀', '✅', '🔥', '💯', '😂', '🤔', '👏', '🙏'];

// Helper to ensure currentUserData is available
async function ensureCurrentUser() {
    if (typeof currentUserData !== 'undefined' && currentUserData) {
        return currentUserData;
    }
    try {
        const response = await fetch('/api/auth/me');
        if (response.ok) {
            const data = await response.json();
            // Store globally if not already
            if (typeof currentUserData === 'undefined') {
                window.currentUserData = data;
            } else {
                currentUserData = data;
            }
            return data;
        }
    } catch (error) {
        console.error('Error fetching current user:', error);
    }
    return null;
}

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', function() {
    initChat();
});

function initChat() {
    // Create chat panel if it doesn't exist
    if (!document.getElementById('chat-panel')) {
        createChatPanel();
    }

    // Load rooms on init
    loadRooms();

    // Start polling when chat is open
    startPolling();
}

function createChatPanel() {
    const panel = document.createElement('div');
    panel.id = 'chat-panel';
    panel.className = 'chat-panel';
    panel.innerHTML = `
        <!-- Room List View -->
        <div class="chat-room-list-view" id="chat-room-list-view">
            <div class="chat-panel-header">
                <h3>Chat</h3>
                <div class="chat-header-actions">
                    <button class="chat-header-btn" onclick="showNewChatModal()" title="New chat">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 5v14M5 12h14"/>
                        </svg>
                    </button>
                    <button class="chat-expand-btn" id="chat-expand-btn" onclick="toggleChatExpand()" title="Expand">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" id="chat-expand-icon">
                            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
                        </svg>
                    </button>
                    <button class="chat-header-btn" onclick="toggleChat()" title="Close">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
            </div>
            <div class="chat-search">
                <input type="text" id="chat-search-input" placeholder="Search conversations..." oninput="filterRooms(this.value)">
            </div>
            <div class="chat-room-list" id="chat-room-list">
                <!-- Rooms populated by JS -->
            </div>
        </div>

        <!-- Active Chat View -->
        <div class="chat-active-view" id="chat-active-view">
            <div class="chat-room-header">
                <button class="chat-back-btn" onclick="closeActiveRoom()">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M15 18l-6-6 6-6"/>
                    </svg>
                </button>
                <div class="chat-room-header-info">
                    <div class="chat-room-header-name" id="chat-room-header-name"></div>
                    <div class="chat-room-header-members" id="chat-room-header-members"></div>
                </div>
            </div>
            <div class="chat-messages" id="chat-messages">
                <!-- Messages populated by JS -->
            </div>
            <div class="typing-indicator" id="typing-indicator" style="display: none;"></div>
            <div class="chat-input-area">
                <div style="position: relative;">
                    <div class="mention-autocomplete" id="mention-autocomplete"></div>
                    <div class="emoji-picker" id="emoji-picker">
                        <div class="emoji-picker-grid">
                            ${COMMON_EMOJIS.map(e => `<div class="emoji-picker-item" onclick="insertEmoji('${e}')">${e}</div>`).join('')}
                        </div>
                    </div>
                    <div class="chat-input-wrapper">
                        <div class="chat-input-actions">
                            <button class="chat-input-btn" onclick="toggleEmojiPicker()" title="Emoji">
                                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"/>
                                    <path d="M8 14s1.5 2 4 2 4-2 4-2"/>
                                    <circle cx="9" cy="9" r="1" fill="currentColor"/>
                                    <circle cx="15" cy="9" r="1" fill="currentColor"/>
                                </svg>
                            </button>
                            <button class="chat-input-btn" onclick="showEnrichHelp()" title="Enrich Observable">
                                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="11" cy="11" r="8"/>
                                    <path d="M21 21l-4.35-4.35"/>
                                </svg>
                            </button>
                        </div>
                        <textarea class="chat-input" id="chat-input" placeholder="Type a message or /enrich ip 1.2.3.4" rows="1"
                            onkeydown="handleInputKeydown(event)"
                            oninput="handleInputChange(event)"></textarea>
                        <button class="chat-send-btn" onclick="sendMessage()" id="chat-send-btn">
                            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(panel);

    // Create modal
    createNewChatModal();
}

function createNewChatModal() {
    const modal = document.createElement('div');
    modal.id = 'new-chat-modal';
    modal.className = 'chat-modal-overlay';
    modal.innerHTML = `
        <div class="chat-modal">
            <div class="chat-modal-header">
                <h3>New Conversation</h3>
                <button class="chat-modal-close" onclick="hideNewChatModal()">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 6L6 18M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <div class="chat-modal-body">
                <div class="user-select-search">
                    <input type="text" id="user-search-input" placeholder="Search users..." oninput="searchUsers(this.value)">
                </div>
                <div class="user-select-list" id="user-select-list">
                    <!-- Users populated by JS -->
                </div>
                <div class="selected-users" id="selected-users"></div>
                <div class="group-name-input" id="group-name-section" style="display: none;">
                    <label for="group-name">Group Name (optional)</label>
                    <input type="text" id="group-name" placeholder="Enter group name...">
                </div>
                <div class="case-link-select" id="case-link-section">
                    <label for="case-link">Link to Case (optional)</label>
                    <select id="case-link">
                        <option value="">No case</option>
                    </select>
                </div>
            </div>
            <div class="chat-modal-footer">
                <button class="btn" onclick="hideNewChatModal()">Cancel</button>
                <button class="btn btn-primary" onclick="createNewChat()" id="create-chat-btn" disabled>Start Chat</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

// =============================================================================
// Chat Toggle
// =============================================================================

function toggleChat() {
    const panel = document.getElementById('chat-panel');
    const toggleBtn = document.getElementById('chat-toggle-btn');

    chatOpen = !chatOpen;

    if (chatOpen) {
        panel.classList.add('open');
        if (toggleBtn) toggleBtn.classList.add('active');
        loadRooms();
    } else {
        panel.classList.remove('open');
        if (toggleBtn) toggleBtn.classList.remove('active');
    }
}

let chatExpanded = false;

function toggleChatExpand() {
    const panel = document.getElementById('chat-panel');
    if (!panel) return;

    chatExpanded = !chatExpanded;
    panel.classList.toggle('expanded', chatExpanded);

    // Swap icon between expand and collapse
    const icon = document.getElementById('chat-expand-icon');
    const btn = document.getElementById('chat-expand-btn');
    if (icon) {
        if (chatExpanded) {
            icon.innerHTML = '<path d="M4 14h6v6M14 4h6v6M3 21l7-7M21 3l-7 7"/>';
            btn.title = 'Collapse';
        } else {
            icon.innerHTML = '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>';
            btn.title = 'Expand';
        }
    }
}

// =============================================================================
// Room Management
// =============================================================================

async function loadRooms() {
    try {
        // Ensure current user is available for filtering
        await ensureCurrentUser();

        const response = await fetch('/api/chat/rooms');
        if (!response.ok) {
            console.error('Failed to load rooms:', response.status);
            return;
        }
        const data = await response.json();
        rooms = data.rooms || [];
        renderRoomList(rooms);
        updateGlobalUnreadBadge();
    } catch (error) {
        console.error('Failed to load rooms:', error);
    }
}

function renderRoomList(roomsToRender) {
    const container = document.getElementById('chat-room-list');
    if (!container) return;

    if (roomsToRender.length === 0) {
        container.innerHTML = `
            <div class="chat-empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
                <p>No conversations yet.<br>Start a new chat!</p>
            </div>
        `;
        return;
    }

    container.innerHTML = roomsToRender.map(room => {
        const avatarClass = room.room_type === 'group' ? 'group' : (room.case_id ? 'case' : '');
        const avatarIcon = room.room_type === 'direct' ? room.display_name?.charAt(0).toUpperCase() || '?' :
                          room.case_id ? '📁' : '👥';
        const unreadClass = room.unread_count > 0 ? 'unread' : '';
        const activeClass = room.id === activeRoomId ? 'active' : '';

        // Build display name with case number if linked
        let displayName = room.display_name || room.name || 'Chat';
        if (room.case_number) {
            displayName = `${room.case_number}` + (room.name ? ` - ${room.name}` : '');
        }

        return `
            <div class="chat-room-item ${unreadClass} ${activeClass}" onclick="openRoom(${room.id})">
                <div class="chat-room-avatar ${avatarClass}">${avatarIcon}</div>
                <div class="chat-room-info">
                    <div class="chat-room-name">
                        <span>${escapeHtml(displayName)}</span>
                        ${room.unread_count > 0 ? `<span class="room-unread-badge">${room.unread_count}</span>` : ''}
                    </div>
                    <div class="chat-room-preview">${escapeHtml(room.last_message || 'No messages yet')}</div>
                </div>
            </div>
        `;
    }).join('');
}

function filterRooms(query) {
    if (!query) {
        renderRoomList(rooms);
        return;
    }

    const filtered = rooms.filter(room => {
        const name = (room.display_name || room.name || '').toLowerCase();
        return name.includes(query.toLowerCase());
    });
    renderRoomList(filtered);
}

async function openRoom(roomId) {
    activeRoomId = roomId;
    lastMessageTimestamp = null;

    // Show active view
    document.getElementById('chat-room-list-view').classList.add('hidden');
    document.getElementById('chat-active-view').classList.add('show');

    // Load room details and messages
    try {
        const [roomData, messagesData] = await Promise.all([
            api.get(`/api/chat/rooms/${roomId}`),
            api.get(`/api/chat/rooms/${roomId}/messages`)
        ]);

        // Update header
        document.getElementById('chat-room-header-name').textContent = roomData.display_name || roomData.name || 'Chat';

        // Show member count
        let headerMeta = roomData.members ? `${roomData.members.length} members` : '';
        document.getElementById('chat-room-header-members').textContent = headerMeta;

        // Show linked case info if any
        renderCaseInfo(roomData.case_info);

        // Render messages
        renderMessages(messagesData.messages || []);

        // Mark as read
        await api.post(`/api/chat/rooms/${roomId}/read`);

        // Update room list to reflect read status
        loadRooms();

    } catch (error) {
        console.error('Failed to open room:', error);
        showToast('Failed to load chat', 'error');
    }
}

function closeActiveRoom() {
    activeRoomId = null;
    lastMessageTimestamp = null;

    document.getElementById('chat-room-list-view').classList.remove('hidden');
    document.getElementById('chat-active-view').classList.remove('show');

    // Refresh room list
    loadRooms();
}

// =============================================================================
// Messages
// =============================================================================

function renderCaseInfo(caseInfo) {
    // Remove existing case info
    const existingInfo = document.getElementById('chat-case-info');
    if (existingInfo) {
        existingInfo.remove();
    }

    if (!caseInfo) return;

    const caseInfoHtml = `
        <div id="chat-case-info" class="chat-case-info">
            <div class="chat-case-header" onclick="toggleCaseInfo()">
                <div class="chat-case-title">
                    <span class="chat-case-badge">${escapeHtml(caseInfo.case_number)}</span>
                    <span class="chat-case-name">${escapeHtml(caseInfo.title)}</span>
                </div>
                <div class="chat-case-toggle">
                    <span class="chat-case-status status-${caseInfo.status?.toLowerCase() || 'open'}">${escapeHtml(caseInfo.status || 'Open')}</span>
                    <svg class="chat-case-chevron" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M6 9l6 6 6-6"/>
                    </svg>
                </div>
            </div>
            <div class="chat-case-details" id="chat-case-details" style="display: none;">
                ${caseInfo.description ? `<div class="chat-case-row"><strong>Description:</strong> ${escapeHtml(caseInfo.description)}</div>` : ''}
                ${caseInfo.severity ? `<div class="chat-case-row"><strong>Severity:</strong> <span class="severity-${caseInfo.severity?.toLowerCase()}">${escapeHtml(caseInfo.severity)}</span></div>` : ''}
                ${caseInfo.assigned_to ? `<div class="chat-case-row"><strong>Assigned to:</strong> ${escapeHtml(caseInfo.assigned_to)}</div>` : ''}
                ${caseInfo.affected_hosts?.length ? `<div class="chat-case-row"><strong>Affected Hosts:</strong> ${caseInfo.affected_hosts.map(h => `<code>${escapeHtml(h)}</code>`).join(', ')}</div>` : ''}
                ${caseInfo.affected_users?.length ? `<div class="chat-case-row"><strong>Affected Users:</strong> ${caseInfo.affected_users.map(u => `<code>${escapeHtml(u)}</code>`).join(', ')}</div>` : ''}
                ${caseInfo.triggered_rules?.length ? `<div class="chat-case-row"><strong>Triggered Rules:</strong> ${caseInfo.triggered_rules.map(r => `<code>${escapeHtml(r)}</code>`).join(', ')}</div>` : ''}
                ${caseInfo.evidence_summary ? `<div class="chat-case-row"><strong>Evidence:</strong> ${escapeHtml(caseInfo.evidence_summary)}</div>` : ''}
                <div class="chat-case-row">
                    <a href="/alerts?case=${caseInfo.id}" class="btn btn-sm" target="_blank">View Full Case</a>
                </div>
            </div>
        </div>
    `;

    // Insert after the room header
    const roomHeader = document.querySelector('.chat-room-header');
    if (roomHeader) {
        roomHeader.insertAdjacentHTML('afterend', caseInfoHtml);
    }
}

function toggleCaseInfo() {
    const details = document.getElementById('chat-case-details');
    const chevron = document.querySelector('.chat-case-chevron');
    if (details) {
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'block' : 'none';
        if (chevron) {
            chevron.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
        }
    }
}

function renderMessages(messages) {
    const container = document.getElementById('chat-messages');
    if (!container) return;

    if (messages.length === 0) {
        container.innerHTML = `
            <div class="chat-empty-state">
                <p>No messages yet. Start the conversation!</p>
            </div>
        `;
        return;
    }

    // Get current user ID - check both local scope and window
    const currentUserId = (typeof currentUserData !== 'undefined' && currentUserData)
        ? currentUserData.id
        : (window.currentUserData ? window.currentUserData.id : null);

    container.innerHTML = messages.map(msg => {
        const isOwn = currentUserId && msg.user_id === currentUserId;
        const ownClass = isOwn ? 'own' : '';
        const content = formatMessageContent(msg.content);

        // Group reactions by emoji
        const reactionGroups = {};
        (msg.reactions || []).forEach(r => {
            if (!reactionGroups[r.emoji]) {
                reactionGroups[r.emoji] = { count: 0, users: [], hasOwn: false };
            }
            reactionGroups[r.emoji].count++;
            reactionGroups[r.emoji].users.push(r.username);
            if (currentUserId && r.user_id === currentUserId) {
                reactionGroups[r.emoji].hasOwn = true;
            }
        });

        const reactionsHtml = Object.entries(reactionGroups).map(([emoji, data]) => `
            <span class="reaction-badge ${data.hasOwn ? 'own' : ''}"
                  onclick="toggleReaction(${msg.id}, '${emoji}')"
                  title="${data.users.join(', ')}">
                <span class="emoji">${emoji}</span>
                <span class="count">${data.count}</span>
            </span>
        `).join('');

        return `
            <div class="chat-message ${ownClass}" data-message-id="${msg.id}">
                <div class="chat-message-header">
                    <span class="chat-message-author">${escapeHtml(msg.display_name || msg.username)}</span>
                    <span class="chat-message-time">${formatTime(msg.created_at)}</span>
                </div>
                <div class="chat-message-content">${content}</div>
                <div class="chat-message-reactions">
                    ${reactionsHtml}
                    <button class="add-reaction-btn" onclick="showReactionPicker(${msg.id})" title="Add reaction">+</button>
                </div>
            </div>
        `;
    }).join('');

    // Update last message timestamp for polling
    if (messages.length > 0) {
        lastMessageTimestamp = messages[messages.length - 1].created_at;
    }

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
}

function formatMessageContent(content) {
    // Escape HTML first
    let formatted = escapeHtml(content);

    // Convert newlines to <br>
    formatted = formatted.replace(/\n/g, '<br>');

    // Convert **bold** to <strong>
    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Convert `code` to <code>
    formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Highlight @mentions
    formatted = formatted.replace(/@(\w+)/g, '<span class="mention">@$1</span>');

    return formatted;
}

function highlightMentions(content) {
    // Replace @username with highlighted span
    return content.replace(/@(\w+)/g, '<span class="mention">@$1</span>');
}

function formatTime(isoString) {
    if (!isoString) return '';
    const date = new Date(isoString);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();

    if (isToday) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
           date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

async function sendMessage() {
    const input = document.getElementById('chat-input');
    const content = input.value.trim();

    if (!content || !activeRoomId) return;

    // Check for /enrich command
    const enrichMatch = content.match(/^\/enrich\s+(\S+)\s+(\S+)$/i);
    if (enrichMatch) {
        await handleEnrichCommand(enrichMatch[1], enrichMatch[2]);
        input.value = '';
        input.style.height = 'auto';
        return;
    }

    // Check for cyber commands (decode/encode/hash)
    const cyberResult = await handleCyberCommand(content);
    if (cyberResult) {
        input.value = '';
        input.style.height = 'auto';
        return;
    }

    // Extract mentions
    const mentionMatches = content.match(/@(\w+)/g) || [];
    const mentions = mentionMatches.map(m => m.substring(1));

    try {
        await api.post(`/api/chat/rooms/${activeRoomId}/messages`, {
            content: content,
            mentions: mentions
        });

        input.value = '';
        input.style.height = 'auto';

        // Refresh messages
        const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
        renderMessages(messagesData.messages || []);

        // Update typing status
        updateTyping(false);

    } catch (error) {
        console.error('Failed to send message:', error);
        showToast('Failed to send message', 'error');
    }
}

async function handleEnrichCommand(type, value) {
    // Map common type aliases
    const typeMap = {
        'ip': 'ipv4-addr',
        'ipv4': 'ipv4-addr',
        'ipv6': 'ipv6-addr',
        'domain': 'domain-name',
        'url': 'url',
        'hash': 'file-hash',
        'md5': 'file-hash',
        'sha1': 'file-hash',
        'sha256': 'file-hash',
        'email': 'email-addr',
        'file': 'file-name'
    };

    const observableType = typeMap[type.toLowerCase()] || type;

    // Post a message indicating enrichment is in progress
    try {
        await api.post(`/api/chat/rooms/${activeRoomId}/messages`, {
            content: `🔍 Enriching ${observableType}: \`${value}\`...`
        });

        // Refresh to show the "enriching" message
        let messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
        renderMessages(messagesData.messages || []);

        // Call OpenCTI enrich API
        const response = await fetch('/api/opencti/enrich', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: observableType, value: value })
        });

        const result = await response.json();

        // Format the results as a message
        let resultMessage = formatEnrichmentResult(observableType, value, result);

        // Post the results
        await api.post(`/api/chat/rooms/${activeRoomId}/messages`, {
            content: resultMessage
        });

        // Refresh messages
        messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
        renderMessages(messagesData.messages || []);

    } catch (error) {
        console.error('Enrichment failed:', error);
        // Post error message
        await api.post(`/api/chat/rooms/${activeRoomId}/messages`, {
            content: `❌ Enrichment failed for ${value}: ${error.message || 'Unknown error'}`
        });
        const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
        renderMessages(messagesData.messages || []);
    }
}

function formatEnrichmentResult(type, value, result) {
    if (result.error) {
        return `❌ **OpenCTI Enrichment Failed**\n` +
               `**Type:** ${type}\n` +
               `**Value:** \`${value}\`\n` +
               `**Error:** ${result.error}`;
    }

    if (!result.found) {
        return `ℹ️ **OpenCTI Enrichment**\n` +
               `**Type:** ${type}\n` +
               `**Value:** \`${value}\`\n` +
               `**Result:** No threat intelligence found for this observable.`;
    }

    // Helper to extract names from array of strings or objects
    const extractNames = (arr) => {
        if (!arr || !arr.length) return null;
        return arr.map(item => {
            if (typeof item === 'string') return item;
            return item.name || item.value || item.title || JSON.stringify(item);
        }).join(', ');
    };

    // Build rich result message
    let msg = `🛡️ **OpenCTI Enrichment Result**\n` +
              `**Type:** ${type}\n` +
              `**Value:** \`${value}\`\n`;

    if (result.score !== undefined && result.score !== null) {
        const scoreEmoji = result.score >= 70 ? '🔴' : result.score >= 40 ? '🟡' : '🟢';
        msg += `**Risk Score:** ${scoreEmoji} ${result.score}/100\n`;
    }

    const labels = extractNames(result.labels);
    if (labels) {
        msg += `**Labels:** ${labels}\n`;
    }

    if (result.description) {
        msg += `**Description:** ${result.description}\n`;
    }

    const malware = extractNames(result.malware_families);
    if (malware) {
        msg += `**Malware Families:** ${malware}\n`;
    }

    const threatActors = extractNames(result.threat_actors);
    if (threatActors) {
        msg += `**Threat Actors:** ${threatActors}\n`;
    }

    const attackPatterns = extractNames(result.attack_patterns);
    if (attackPatterns) {
        msg += `**MITRE ATT&CK:** ${attackPatterns}\n`;
    }

    const countries = extractNames(result.countries);
    if (countries) {
        msg += `**Countries:** ${countries}\n`;
    }

    if (result.first_seen) {
        msg += `**First Seen:** ${result.first_seen}\n`;
    }

    if (result.last_seen) {
        msg += `**Last Seen:** ${result.last_seen}\n`;
    }

    if (result.external_references && result.external_references.length > 0) {
        const refs = result.external_references.slice(0, 3).map(r => {
            if (typeof r === 'string') return r;
            return r.url || r.source_name || r.name || '';
        }).filter(r => r).join(', ');
        if (refs) {
            msg += `**References:** ${refs}\n`;
        }
    }

    return msg;
}

// =============================================================================
// Polling
// =============================================================================

function startPolling() {
    if (pollInterval) return;

    pollInterval = setInterval(async () => {
        if (!chatOpen) return;

        // Poll for new messages if in active room
        if (activeRoomId) {
            await pollMessages();
            await pollTyping();
        }

        // Always update unread counts
        await updateUnreadCounts();
    }, POLL_INTERVAL_MS);
}

async function pollMessages() {
    if (!activeRoomId) return;

    try {
        const url = lastMessageTimestamp
            ? `/api/chat/rooms/${activeRoomId}/messages?since=${encodeURIComponent(lastMessageTimestamp)}`
            : `/api/chat/rooms/${activeRoomId}/messages`;

        const data = await api.get(url);

        if (data.messages && data.messages.length > 0) {
            // Append new messages
            const container = document.getElementById('chat-messages');
            const existingIds = new Set(
                Array.from(container.querySelectorAll('.chat-message'))
                     .map(el => parseInt(el.dataset.messageId))
            );

            const newMessages = data.messages.filter(m => !existingIds.has(m.id));

            if (newMessages.length > 0) {
                // Re-render all messages for simplicity
                const allData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
                renderMessages(allData.messages || []);

                // Mark as read
                await api.post(`/api/chat/rooms/${activeRoomId}/read`);
            }
        }
    } catch (error) {
        console.error('Poll messages error:', error);
    }
}

async function pollTyping() {
    if (!activeRoomId) return;

    try {
        const data = await api.get(`/api/chat/rooms/${activeRoomId}/typing`);
        renderTypingIndicator(data.typing_users || []);
    } catch (error) {
        // Silently ignore typing poll errors
    }
}

function renderTypingIndicator(users) {
    const indicator = document.getElementById('typing-indicator');
    if (!indicator) return;

    // Get current user ID
    const currentUserId = (typeof currentUserData !== 'undefined' && currentUserData)
        ? currentUserData.id
        : (window.currentUserData ? window.currentUserData.id : null);

    // Filter out current user
    const othersTyping = users.filter(u => !currentUserId || u.id !== currentUserId);

    if (othersTyping.length === 0) {
        indicator.style.display = 'none';
        return;
    }

    const names = othersTyping.map(u => u.display_name || u.username);
    const text = names.length === 1
        ? `${names[0]} is typing`
        : names.length === 2
            ? `${names[0]} and ${names[1]} are typing`
            : `${names.length} people are typing`;

    indicator.innerHTML = `${text}<span class="typing-dots"><span></span><span></span><span></span></span>`;
    indicator.style.display = 'block';
}

async function updateUnreadCounts() {
    try {
        const data = await api.get('/api/chat/rooms');
        rooms = data.rooms || [];

        // Only update room list if not viewing a specific room
        if (!activeRoomId) {
            renderRoomList(rooms);
        }

        updateGlobalUnreadBadge();
    } catch (error) {
        // Silently ignore
    }
}

function updateGlobalUnreadBadge() {
    const totalUnread = rooms.reduce((sum, r) => sum + (r.unread_count || 0), 0);
    const badge = document.getElementById('chat-unread-badge');
    const toggleBtn = document.getElementById('chat-toggle-btn');

    if (badge) {
        if (totalUnread > 0) {
            badge.textContent = totalUnread > 99 ? '99+' : totalUnread;
            badge.style.display = 'flex';
            if (toggleBtn) toggleBtn.classList.add('has-unread');
        } else {
            badge.style.display = 'none';
            if (toggleBtn) toggleBtn.classList.remove('has-unread');
        }
    }
}

// =============================================================================
// Typing Indicator
// =============================================================================

function handleInputChange(event) {
    const input = event.target;

    // Auto-resize textarea
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';

    // Update typing status
    updateTyping(true);

    // Check for @mention
    checkForMention(input);
}

function handleInputKeydown(event) {
    const autocomplete = document.getElementById('mention-autocomplete');
    const isAutocompleteVisible = autocomplete && autocomplete.classList.contains('show');

    if (event.key === 'Enter' && !event.shiftKey) {
        if (isAutocompleteVisible) {
            event.preventDefault();
            selectMention();
        } else {
            event.preventDefault();
            sendMessage();
        }
    } else if (isAutocompleteVisible) {
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            navigateMention(1);
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            navigateMention(-1);
        } else if (event.key === 'Escape') {
            hideMentionAutocomplete();
        }
    }
}

async function updateTyping(isTyping) {
    if (!activeRoomId) return;

    // Clear existing timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }

    // Set new timeout to stop typing after inactivity
    if (isTyping) {
        typingTimeout = setTimeout(() => {
            updateTyping(false);
        }, TYPING_TIMEOUT_MS);
    }

    try {
        await api.post(`/api/chat/rooms/${activeRoomId}/typing`, {
            is_typing: isTyping
        });
    } catch (error) {
        // Silently ignore
    }
}

// =============================================================================
// Mentions
// =============================================================================

async function checkForMention(input) {
    const value = input.value;
    const cursorPos = input.selectionStart;

    // Find @ before cursor
    const beforeCursor = value.substring(0, cursorPos);
    const atMatch = beforeCursor.match(/@(\w*)$/);

    if (atMatch) {
        const query = atMatch[1];
        await loadMentionUsers(query);
    } else {
        hideMentionAutocomplete();
    }
}

async function loadMentionUsers(query) {
    try {
        const data = await api.get(`/api/chat/users?q=${encodeURIComponent(query)}`);
        mentionUsers = data.users || [];
        selectedMentionIndex = 0;
        renderMentionAutocomplete();
    } catch (error) {
        hideMentionAutocomplete();
    }
}

function renderMentionAutocomplete() {
    const container = document.getElementById('mention-autocomplete');
    if (!container) return;

    if (mentionUsers.length === 0) {
        hideMentionAutocomplete();
        return;
    }

    container.innerHTML = mentionUsers.map((user, index) => `
        <div class="mention-item ${index === selectedMentionIndex ? 'selected' : ''}"
             onclick="selectMention(${index})">
            <div class="mention-item-avatar">${(user.display_name || user.username).charAt(0).toUpperCase()}</div>
            <div>
                <div class="mention-item-name">${escapeHtml(user.display_name || user.username)}</div>
                <div class="mention-item-username">@${escapeHtml(user.username)}</div>
            </div>
        </div>
    `).join('');

    container.classList.add('show');
}

function hideMentionAutocomplete() {
    const container = document.getElementById('mention-autocomplete');
    if (container) {
        container.classList.remove('show');
    }
    mentionUsers = [];
}

function navigateMention(direction) {
    selectedMentionIndex = Math.max(0, Math.min(mentionUsers.length - 1, selectedMentionIndex + direction));
    renderMentionAutocomplete();
}

function selectMention(index) {
    if (index !== undefined) {
        selectedMentionIndex = index;
    }

    const user = mentionUsers[selectedMentionIndex];
    if (!user) return;

    const input = document.getElementById('chat-input');
    const value = input.value;
    const cursorPos = input.selectionStart;

    // Find and replace the @query
    const beforeCursor = value.substring(0, cursorPos);
    const afterCursor = value.substring(cursorPos);
    const atMatch = beforeCursor.match(/@(\w*)$/);

    if (atMatch) {
        const newBefore = beforeCursor.substring(0, beforeCursor.length - atMatch[0].length);
        input.value = newBefore + '@' + user.username + ' ' + afterCursor;
        input.selectionStart = input.selectionEnd = newBefore.length + user.username.length + 2;
    }

    hideMentionAutocomplete();
    input.focus();
}

// =============================================================================
// Reactions
// =============================================================================

async function toggleReaction(messageId, emoji) {
    try {
        // Check if user already has this reaction
        const container = document.querySelector(`.chat-message[data-message-id="${messageId}"]`);
        const badge = container?.querySelector(`.reaction-badge[onclick*="'${emoji}'"]`);
        const hasOwn = badge?.classList.contains('own');

        if (hasOwn) {
            await api.delete(`/api/chat/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`);
        } else {
            await api.post(`/api/chat/messages/${messageId}/reactions`, { emoji });
        }

        // Refresh messages to show updated reactions
        const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
        renderMessages(messagesData.messages || []);
    } catch (error) {
        console.error('Failed to toggle reaction:', error);
    }
}

function showReactionPicker(messageId) {
    // Simple inline picker - show common emojis
    const picker = document.createElement('div');
    picker.className = 'emoji-picker show';
    picker.style.position = 'absolute';
    picker.innerHTML = `
        <div class="emoji-picker-grid">
            ${COMMON_EMOJIS.slice(0, 6).map(e =>
                `<div class="emoji-picker-item" onclick="addReaction(${messageId}, '${e}')">${e}</div>`
            ).join('')}
        </div>
    `;

    const msgEl = document.querySelector(`.chat-message[data-message-id="${messageId}"]`);
    const reactionsEl = msgEl?.querySelector('.chat-message-reactions');
    if (reactionsEl) {
        // Remove any existing picker
        reactionsEl.querySelectorAll('.emoji-picker').forEach(p => p.remove());
        reactionsEl.appendChild(picker);

        // Close on click outside
        setTimeout(() => {
            document.addEventListener('click', function closePicker(e) {
                if (!picker.contains(e.target)) {
                    picker.remove();
                    document.removeEventListener('click', closePicker);
                }
            });
        }, 0);
    }
}

async function addReaction(messageId, emoji) {
    await toggleReaction(messageId, emoji);
}

// =============================================================================
// Emoji Picker
// =============================================================================

function toggleEmojiPicker() {
    const picker = document.getElementById('emoji-picker');
    if (picker) {
        picker.classList.toggle('show');
    }
}

function insertEmoji(emoji) {
    const input = document.getElementById('chat-input');
    const pos = input.selectionStart;
    const value = input.value;

    input.value = value.substring(0, pos) + emoji + value.substring(pos);
    input.selectionStart = input.selectionEnd = pos + emoji.length;
    input.focus();

    toggleEmojiPicker();
}

// =============================================================================
// New Chat Modal
// =============================================================================

let selectedUsers = [];
let availableUsers = [];

async function showNewChatModal() {
    selectedUsers = [];
    document.getElementById('new-chat-modal').classList.add('show');
    document.getElementById('user-search-input').value = '';
    document.getElementById('group-name').value = '';
    document.getElementById('case-link').value = '';
    document.getElementById('selected-users').innerHTML = '';
    document.getElementById('user-select-list').innerHTML = '<div style="padding: 1rem; color: var(--text-muted); text-align: center; font-size: 0.8125rem;">Loading users...</div>';
    updateCreateButton();

    // Ensure current user is loaded before loading available users
    await ensureCurrentUser();

    await loadAvailableUsers();
    loadCases();
}

function hideNewChatModal() {
    document.getElementById('new-chat-modal').classList.remove('show');
}

async function loadAvailableUsers() {
    try {
        const response = await fetch('/api/chat/users');
        if (!response.ok) {
            console.error('Failed to load users, status:', response.status);
            // Show error in user list
            const container = document.getElementById('user-select-list');
            if (container) {
                container.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); text-align: center;">Failed to load users</div>';
            }
            return;
        }
        const data = await response.json();
        // Get current user ID
        const currentUserId = (typeof currentUserData !== 'undefined' && currentUserData)
            ? currentUserData.id
            : (window.currentUserData ? window.currentUserData.id : null);
        // Filter out current user if we know who they are
        availableUsers = (data.users || []).filter(u => !currentUserId || u.id !== currentUserId);
        console.log('Loaded', availableUsers.length, 'users for chat');
        renderUserList(availableUsers);
    } catch (error) {
        console.error('Failed to load users:', error);
        const container = document.getElementById('user-select-list');
        if (container) {
            container.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); text-align: center;">Error loading users</div>';
        }
    }
}

async function loadCases() {
    try {
        const response = await fetch('/api/elasticsearch/alerts/cases');
        if (!response.ok) {
            console.log('Cases API not available or returned error');
            return;
        }
        const data = await response.json();
        const select = document.getElementById('case-link');
        if (select && data.cases && data.cases.length > 0) {
            select.innerHTML = '<option value="">No case</option>' +
                data.cases.map(c =>
                    `<option value="${c.id}">${escapeHtml(c.case_number)} - ${escapeHtml(c.title)}</option>`
                ).join('');
        }
    } catch (error) {
        console.log('Cases API error (may not exist):', error.message);
    }
}

function searchUsers(query) {
    if (!query) {
        renderUserList(availableUsers);
        return;
    }

    const filtered = availableUsers.filter(u => {
        const name = (u.display_name || u.username).toLowerCase();
        return name.includes(query.toLowerCase()) || u.username.toLowerCase().includes(query.toLowerCase());
    });
    renderUserList(filtered);
}

function renderUserList(users) {
    const container = document.getElementById('user-select-list');
    if (!container) return;

    if (!users || users.length === 0) {
        container.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); text-align: center; font-size: 0.8125rem;">No users available</div>';
        return;
    }

    container.innerHTML = users.map(user => {
        const isSelected = selectedUsers.some(u => u.id === user.id);
        return `
            <div class="user-select-item ${isSelected ? 'selected' : ''}" onclick="toggleUserSelection(${user.id})">
                <input type="checkbox" ${isSelected ? 'checked' : ''} onclick="event.stopPropagation(); toggleUserSelection(${user.id})">
                <div class="mention-item-avatar">${(user.display_name || user.username).charAt(0).toUpperCase()}</div>
                <div>
                    <div class="mention-item-name">${escapeHtml(user.display_name || user.username)}</div>
                    <div class="mention-item-username">@${escapeHtml(user.username)}</div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleUserSelection(userId) {
    console.log('toggleUserSelection called with userId:', userId);
    console.log('availableUsers:', availableUsers);
    const user = availableUsers.find(u => u.id === userId);
    if (!user) {
        console.log('User not found in availableUsers');
        return;
    }

    const index = selectedUsers.findIndex(u => u.id === userId);
    if (index >= 0) {
        selectedUsers.splice(index, 1);
        console.log('Removed user from selection');
    } else {
        selectedUsers.push(user);
        console.log('Added user to selection');
    }
    console.log('selectedUsers now:', selectedUsers);

    renderUserList(availableUsers.filter(u => {
        const searchValue = document.getElementById('user-search-input')?.value || '';
        if (!searchValue) return true;
        const name = (u.display_name || u.username).toLowerCase();
        return name.includes(searchValue.toLowerCase());
    }));
    renderSelectedUsers();
    updateCreateButton();
}

function renderSelectedUsers() {
    const container = document.getElementById('selected-users');
    const groupSection = document.getElementById('group-name-section');

    if (!container) return;

    container.innerHTML = selectedUsers.map(user => `
        <span class="selected-user-tag">
            ${escapeHtml(user.display_name || user.username)}
            <button onclick="toggleUserSelection(${user.id})">×</button>
        </span>
    `).join('');

    // Show group name input if more than 1 user selected
    if (groupSection) {
        groupSection.style.display = selectedUsers.length > 1 ? 'block' : 'none';
    }
}

function updateCreateButton() {
    const btn = document.getElementById('create-chat-btn');
    if (btn) {
        btn.disabled = selectedUsers.length === 0;
    }
}

async function createNewChat() {
    console.log('createNewChat called, selectedUsers:', selectedUsers);
    if (selectedUsers.length === 0) {
        console.log('No users selected, returning');
        return;
    }

    const groupName = document.getElementById('group-name')?.value || null;
    const caseId = document.getElementById('case-link')?.value || null;

    // If a case is linked, always create a group chat (even for 2 people)
    // Direct messages are only for 1-on-1 without case links
    const roomType = (selectedUsers.length === 1 && !caseId) ? 'direct' : 'group';

    console.log('Creating room:', { roomType, groupName, caseId, member_ids: selectedUsers.map(u => u.id) });

    try {
        const data = await api.post('/api/chat/rooms', {
            room_type: roomType,
            name: groupName,
            case_id: caseId ? parseInt(caseId) : null,
            member_ids: selectedUsers.map(u => u.id)
        });

        console.log('Room created:', data);
        hideNewChatModal();
        await loadRooms();

        // Open the new room (or existing one for DMs)
        if (data.room_id) {
            // Make sure chat panel is open
            const panel = document.getElementById('chat-panel');
            if (panel && !panel.classList.contains('open')) {
                panel.classList.add('open');
                chatOpen = true;
            }
            await openRoom(data.room_id);
        }

    } catch (error) {
        console.error('Failed to create chat:', error);
        showToast('Failed to create chat', 'error');
    }
}

// =============================================================================
// Enrich Help
// =============================================================================

// =============================================================================
// Cyber Commands (Safe decode/encode - no eval, no dynamic execution)
// =============================================================================

async function handleCyberCommand(content) {
    // Match command pattern: /command value
    const match = content.match(/^\/(\w+)\s+(.+)$/s);
    if (!match) return false;

    const command = match[1].toLowerCase();
    const value = match[2].trim();

    // Map of safe, hardcoded operations only
    const operations = {
        // Base64
        'b64d': () => safeBase64Decode(value),
        'b64e': () => safeBase64Encode(value),
        'base64d': () => safeBase64Decode(value),
        'base64e': () => safeBase64Encode(value),

        // URL encoding
        'urld': () => safeUrlDecode(value),
        'urle': () => safeUrlEncode(value),
        'urldecode': () => safeUrlDecode(value),
        'urlencode': () => safeUrlEncode(value),

        // Hex
        'hexd': () => safeHexDecode(value),
        'hexe': () => safeHexEncode(value),
        'hexdecode': () => safeHexDecode(value),
        'hexencode': () => safeHexEncode(value),

        // ROT13
        'rot13': () => safeRot13(value),

        // Reverse
        'reverse': () => ({ result: [...value].reverse().join(''), operation: 'Reverse' }),

        // Defang/Refang for safe IOC sharing
        'defang': () => safeDefang(value),
        'refang': () => safeRefang(value),

        // Hashing (using Web Crypto API)
        'md5': () => safeHash('MD5', value),
        'sha1': () => safeHash('SHA-1', value),
        'sha256': () => safeHash('SHA-256', value),

        // String analysis
        'len': () => ({ result: `${value.length} characters`, operation: 'Length' }),
        'lower': () => ({ result: value.toLowerCase(), operation: 'Lowercase' }),
        'upper': () => ({ result: value.toUpperCase(), operation: 'Uppercase' }),

        // Help
        'cyber': () => showCyberHelp(),
    };

    const operation = operations[command];
    if (!operation) return false;

    try {
        const result = await operation();
        if (result && result.result !== undefined) {
            await postCyberResult(value, result.operation, result.result);
        }
        return true;
    } catch (error) {
        await postCyberError(command, value, error.message);
        return true;
    }
}

// Safe Base64 decode - handles UTF-8
function safeBase64Decode(input) {
    try {
        // Handle URL-safe base64
        const sanitized = input.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = atob(sanitized);
        // Try to decode as UTF-8
        try {
            const result = decodeURIComponent(escape(decoded));
            return { result, operation: 'Base64 Decode' };
        } catch {
            return { result: decoded, operation: 'Base64 Decode' };
        }
    } catch (e) {
        throw new Error('Invalid Base64 input');
    }
}

// Safe Base64 encode
function safeBase64Encode(input) {
    try {
        const result = btoa(unescape(encodeURIComponent(input)));
        return { result, operation: 'Base64 Encode' };
    } catch (e) {
        throw new Error('Failed to encode');
    }
}

// Safe URL decode
function safeUrlDecode(input) {
    try {
        const result = decodeURIComponent(input);
        return { result, operation: 'URL Decode' };
    } catch (e) {
        throw new Error('Invalid URL encoding');
    }
}

// Safe URL encode
function safeUrlEncode(input) {
    const result = encodeURIComponent(input);
    return { result, operation: 'URL Encode' };
}

// Safe Hex decode
function safeHexDecode(input) {
    const hex = input.replace(/\s+/g, '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
        throw new Error('Invalid hex input');
    }
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return { result, operation: 'Hex Decode' };
}

// Safe Hex encode
function safeHexEncode(input) {
    let result = '';
    for (let i = 0; i < input.length; i++) {
        result += input.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return { result, operation: 'Hex Encode' };
}

// Safe ROT13
function safeRot13(input) {
    const result = input.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    return { result, operation: 'ROT13' };
}

// Safe defang for IOC sharing
function safeDefang(input) {
    let result = input
        .replace(/\./g, '[.]')
        .replace(/http/gi, 'hxxp')
        .replace(/:\/\//g, '[://]')
        .replace(/@/g, '[@]');
    return { result, operation: 'Defang' };
}

// Safe refang
function safeRefang(input) {
    let result = input
        .replace(/\[\.\]/g, '.')
        .replace(/hxxp/gi, 'http')
        .replace(/\[:\/\/\]/g, '://')
        .replace(/\[@\]/g, '@');
    return { result, operation: 'Refang' };
}

// Safe hashing using Web Crypto API
async function safeHash(algorithm, input) {
    // MD5 not supported by Web Crypto, use simple implementation for display only
    if (algorithm === 'MD5') {
        const result = simpleMD5(input);
        return { result, operation: 'MD5 Hash' };
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const result = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return { result, operation: `${algorithm} Hash` };
}

// Simple MD5 implementation (for display purposes - not cryptographically secure)
function simpleMD5(string) {
    function rotateLeft(value, shift) {
        return (value << shift) | (value >>> (32 - shift));
    }
    function addUnsigned(x, y) {
        const x4 = (x & 0x40000000), y4 = (y & 0x40000000);
        const x8 = (x & 0x80000000), y8 = (y & 0x80000000);
        const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
        if (x4 & y4) return (result ^ 0x80000000 ^ x8 ^ y8);
        if (x4 | y4) {
            if (result & 0x40000000) return (result ^ 0xC0000000 ^ x8 ^ y8);
            else return (result ^ 0x40000000 ^ x8 ^ y8);
        } else return (result ^ x8 ^ y8);
    }
    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }
    function FF(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function GG(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function HH(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function II(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function convertToWordArray(str) {
        let wordCount, messageLength = str.length, temp1 = messageLength + 8;
        let temp2 = (temp1 - (temp1 % 64)) / 64, numWords = (temp2 + 1) * 16;
        let wordArray = Array(numWords - 1), bytePos = 0, byteCount = 0;
        while (byteCount < messageLength) {
            wordCount = (byteCount - (byteCount % 4)) / 4;
            bytePos = (byteCount % 4) * 8;
            wordArray[wordCount] = (wordArray[wordCount] || 0) | (str.charCodeAt(byteCount) << bytePos);
            byteCount++;
        }
        wordCount = (byteCount - (byteCount % 4)) / 4;
        bytePos = (byteCount % 4) * 8;
        wordArray[wordCount] = (wordArray[wordCount] || 0) | (0x80 << bytePos);
        wordArray[numWords - 2] = messageLength << 3;
        wordArray[numWords - 1] = messageLength >>> 29;
        return wordArray;
    }
    function wordToHex(value) {
        let hex = '', temp, byte;
        for (byte = 0; byte <= 3; byte++) {
            temp = (value >>> (byte * 8)) & 255;
            hex += ('0' + temp.toString(16)).slice(-2);
        }
        return hex;
    }

    let x = convertToWordArray(string);
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    const S11=7, S12=12, S13=17, S14=22, S21=5, S22=9, S23=14, S24=20;
    const S31=4, S32=11, S33=16, S34=23, S41=6, S42=10, S43=15, S44=21;

    for (let k = 0; k < x.length; k += 16) {
        let AA = a, BB = b, CC = c, DD = d;
        a = FF(a,b,c,d,x[k+0],S11,0xD76AA478); d = FF(d,a,b,c,x[k+1],S12,0xE8C7B756);
        c = FF(c,d,a,b,x[k+2],S13,0x242070DB); b = FF(b,c,d,a,x[k+3],S14,0xC1BDCEEE);
        a = FF(a,b,c,d,x[k+4],S11,0xF57C0FAF); d = FF(d,a,b,c,x[k+5],S12,0x4787C62A);
        c = FF(c,d,a,b,x[k+6],S13,0xA8304613); b = FF(b,c,d,a,x[k+7],S14,0xFD469501);
        a = FF(a,b,c,d,x[k+8],S11,0x698098D8); d = FF(d,a,b,c,x[k+9],S12,0x8B44F7AF);
        c = FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1); b = FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
        a = FF(a,b,c,d,x[k+12],S11,0x6B901122); d = FF(d,a,b,c,x[k+13],S12,0xFD987193);
        c = FF(c,d,a,b,x[k+14],S13,0xA679438E); b = FF(b,c,d,a,x[k+15],S14,0x49B40821);
        a = GG(a,b,c,d,x[k+1],S21,0xF61E2562); d = GG(d,a,b,c,x[k+6],S22,0xC040B340);
        c = GG(c,d,a,b,x[k+11],S23,0x265E5A51); b = GG(b,c,d,a,x[k+0],S24,0xE9B6C7AA);
        a = GG(a,b,c,d,x[k+5],S21,0xD62F105D); d = GG(d,a,b,c,x[k+10],S22,0x2441453);
        c = GG(c,d,a,b,x[k+15],S23,0xD8A1E681); b = GG(b,c,d,a,x[k+4],S24,0xE7D3FBC8);
        a = GG(a,b,c,d,x[k+9],S21,0x21E1CDE6); d = GG(d,a,b,c,x[k+14],S22,0xC33707D6);
        c = GG(c,d,a,b,x[k+3],S23,0xF4D50D87); b = GG(b,c,d,a,x[k+8],S24,0x455A14ED);
        a = GG(a,b,c,d,x[k+13],S21,0xA9E3E905); d = GG(d,a,b,c,x[k+2],S22,0xFCEFA3F8);
        c = GG(c,d,a,b,x[k+7],S23,0x676F02D9); b = GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
        a = HH(a,b,c,d,x[k+5],S31,0xFFFA3942); d = HH(d,a,b,c,x[k+8],S32,0x8771F681);
        c = HH(c,d,a,b,x[k+11],S33,0x6D9D6122); b = HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
        a = HH(a,b,c,d,x[k+1],S31,0xA4BEEA44); d = HH(d,a,b,c,x[k+4],S32,0x4BDECFA9);
        c = HH(c,d,a,b,x[k+7],S33,0xF6BB4B60); b = HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
        a = HH(a,b,c,d,x[k+13],S31,0x289B7EC6); d = HH(d,a,b,c,x[k+0],S32,0xEAA127FA);
        c = HH(c,d,a,b,x[k+3],S33,0xD4EF3085); b = HH(b,c,d,a,x[k+6],S34,0x4881D05);
        a = HH(a,b,c,d,x[k+9],S31,0xD9D4D039); d = HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
        c = HH(c,d,a,b,x[k+15],S33,0x1FA27CF8); b = HH(b,c,d,a,x[k+2],S34,0xC4AC5665);
        a = II(a,b,c,d,x[k+0],S41,0xF4292244); d = II(d,a,b,c,x[k+7],S42,0x432AFF97);
        c = II(c,d,a,b,x[k+14],S43,0xAB9423A7); b = II(b,c,d,a,x[k+5],S44,0xFC93A039);
        a = II(a,b,c,d,x[k+12],S41,0x655B59C3); d = II(d,a,b,c,x[k+3],S42,0x8F0CCC92);
        c = II(c,d,a,b,x[k+10],S43,0xFFEFF47D); b = II(b,c,d,a,x[k+1],S44,0x85845DD1);
        a = II(a,b,c,d,x[k+8],S41,0x6FA87E4F); d = II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
        c = II(c,d,a,b,x[k+6],S43,0xA3014314); b = II(b,c,d,a,x[k+13],S44,0x4E0811A1);
        a = II(a,b,c,d,x[k+4],S41,0xF7537E82); d = II(d,a,b,c,x[k+11],S42,0xBD3AF235);
        c = II(c,d,a,b,x[k+2],S43,0x2AD7D2BB); b = II(b,c,d,a,x[k+9],S44,0xEB86D391);
        a = addUnsigned(a, AA); b = addUnsigned(b, BB); c = addUnsigned(c, CC); d = addUnsigned(d, DD);
    }
    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// Post cyber command result to chat
async function postCyberResult(input, operation, result) {
    const message = `🔧 **${operation}**\n` +
                   `**Input:** \`${input.length > 100 ? input.substring(0, 100) + '...' : input}\`\n` +
                   `**Output:** \`${result}\``;

    await api.post(`/api/chat/rooms/${activeRoomId}/messages`, { content: message });
    const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
    renderMessages(messagesData.messages || []);
}

// Post cyber command error
async function postCyberError(command, input, error) {
    const message = `❌ **${command} failed**\n` +
                   `**Input:** \`${input.length > 50 ? input.substring(0, 50) + '...' : input}\`\n` +
                   `**Error:** ${error}`;

    await api.post(`/api/chat/rooms/${activeRoomId}/messages`, { content: message });
    const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
    renderMessages(messagesData.messages || []);
}

// Show cyber commands help
async function showCyberHelp() {
    const helpMessage = `🔧 **Cyber Commands Help**

**Encoding/Decoding:**
\`/b64e <text>\` - Base64 encode
\`/b64d <text>\` - Base64 decode
\`/urle <text>\` - URL encode
\`/urld <text>\` - URL decode
\`/hexe <text>\` - Hex encode
\`/hexd <hex>\` - Hex decode
\`/rot13 <text>\` - ROT13

**Hashing:**
\`/md5 <text>\` - MD5 hash
\`/sha1 <text>\` - SHA-1 hash
\`/sha256 <text>\` - SHA-256 hash

**IOC Tools:**
\`/defang <ioc>\` - Defang URL/IP
\`/refang <ioc>\` - Refang URL/IP
\`/enrich <type> <value>\` - OpenCTI lookup

**String Tools:**
\`/reverse <text>\` - Reverse string
\`/upper <text>\` - Uppercase
\`/lower <text>\` - Lowercase
\`/len <text>\` - String length`;

    await api.post(`/api/chat/rooms/${activeRoomId}/messages`, { content: helpMessage });
    const messagesData = await api.get(`/api/chat/rooms/${activeRoomId}/messages`);
    renderMessages(messagesData.messages || []);
    return { result: '', operation: '' };
}

function showEnrichHelp() {
    // Insert /cyber to show help in chat
    const input = document.getElementById('chat-input');
    if (input) {
        input.value = '/cyber help';
        input.focus();
        showToast('Press Enter to see all commands', 'info');
    }
}

// =============================================================================
// Close pickers on outside click
// =============================================================================

document.addEventListener('click', function(event) {
    const emojiPicker = document.getElementById('emoji-picker');
    const emojiBtn = event.target.closest('.chat-input-btn');

    if (emojiPicker && emojiPicker.classList.contains('show') && !emojiBtn && !emojiPicker.contains(event.target)) {
        emojiPicker.classList.remove('show');
    }
});
