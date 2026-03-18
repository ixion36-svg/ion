// ION Web UI JavaScript

/**
 * Render markdown to sanitized HTML. All user-controlled markdown
 * MUST go through this function — never use marked.parse() directly.
 */
function safeMarkdown(content) {
    if (!content) return '';
    const raw = (typeof marked !== 'undefined') ? marked.parse(content) : content;
    return (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(raw) : raw;
}

// API helper
const api = {
    async request(method, url, data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Request failed' }));
            throw new Error(error.detail || 'Request failed');
        }

        return response.json();
    },

    get(url) {
        return this.request('GET', url);
    },

    post(url, data) {
        return this.request('POST', url, data);
    },

    put(url, data) {
        return this.request('PUT', url, data);
    },

    delete(url) {
        return this.request('DELETE', url);
    },
};

// Utility functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Debounce helper
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// =============================================================================
// User Menu & Authentication
// =============================================================================

let currentUserData = null;
let _loadUserPromise = null;

// Restore cached user data immediately so nav renders without flash
try {
    const cached = sessionStorage.getItem('ion_user');
    if (cached) {
        currentUserData = JSON.parse(cached);
    }
} catch {}

async function loadCurrentUser() {
    // Deduplicate — return existing promise if already in flight
    if (_loadUserPromise) return _loadUserPromise;

    _loadUserPromise = (async () => {
        try {
            const response = await fetch('/api/auth/me');
            if (response.status === 401) {
                sessionStorage.removeItem('ion_user');
                if (!window.location.pathname.startsWith('/login')) {
                    window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
                }
                return;
            }
            if (response.ok) {
                currentUserData = await response.json();
                sessionStorage.setItem('ion_user', JSON.stringify(currentUserData));
                updateUserMenu();
            }
        } catch (error) {
            console.error('Error loading user:', error);
        } finally {
            _loadUserPromise = null;
        }
    })();
    return _loadUserPromise;
}

function updateUserMenu() {
    if (!currentUserData) return;

    const userAvatar = document.getElementById('user-avatar');
    const userName = document.getElementById('user-name');
    const dropdownHeader = document.getElementById('user-dropdown-header');

    if (userAvatar) {
        userAvatar.textContent = currentUserData.username.charAt(0).toUpperCase();
    }
    if (userName) {
        userName.textContent = currentUserData.display_name || currentUserData.username;
    }
    if (dropdownHeader) {
        const roles = currentUserData.roles.map(r => `<span class="role-badge role-${r}">${r}</span>`).join(' ');
        // Focus mode selector — only show if user has multiple roles
        let focusHtml = '';
        if (currentUserData.roles.length > 1) {
            const activeRole = currentUserData.focus_role || '';
            const opts = ['<option value=""' + (!activeRole ? ' selected' : '') + '>All Roles</option>'];
            currentUserData.roles.forEach(r => {
                opts.push('<option value="' + r + '"' + (activeRole === r ? ' selected' : '') + '>' + r.charAt(0).toUpperCase() + r.slice(1) + '</option>');
            });
            focusHtml = `
                <div class="dropdown-focus" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border-color,#30363d);">
                    <label style="font-size:.75rem;color:var(--text-muted);display:block;margin-bottom:4px;">Focus Mode</label>
                    <select id="focus-mode-select" class="form-input" style="width:100%;padding:4px 8px;font-size:.8rem;" onchange="switchFocusMode(this.value)">
                        ${opts.join('')}
                    </select>
                </div>
            `;
        }
        dropdownHeader.innerHTML = `
            <div class="dropdown-user-info">
                <strong>${escapeHtml(currentUserData.display_name || currentUserData.username)}</strong>
                <span class="dropdown-email">${escapeHtml(currentUserData.email)}</span>
            </div>
            <div class="dropdown-roles">${roles}</div>
            ${focusHtml}
        `;
    }

    updateNavForPermissions();
}

function updateNavForPermissions() {
    if (!currentUserData) return;

    // Use permissions array (already filtered by focus mode on the server)
    const perms = new Set(currentUserData.permissions || []);
    const roles = currentUserData.focus_role ? [currentUserData.focus_role] : currentUserData.roles;

    const isAdmin = roles.includes('admin');
    const isEngineer = ['engineering', 'admin'].some(r => roles.includes(r));

    // Permission-based nav visibility — security links shown if user has security:read
    ['nav-security-link', 'nav-topology-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = perms.has('security:read') ? '' : 'none';
    });

    // Engineer+ links (engineering/admin) — integration & settings access
    ['nav-integrations-link', 'nav-settings-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isEngineer ? '' : 'none';
    });

    // Admin only links
    ['nav-admin-links', 'nav-audit-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isAdmin ? '' : 'none';
    });

    // Forensics link — only visible when user has forensic:read
    const forensicsLink = document.getElementById('nav-forensics-link');
    if (forensicsLink) {
        forensicsLink.style.display = perms.has('forensic:read') ? '' : 'none';
    }

    // Hide dropdown groups where ALL children are hidden
    ['nav-group-engineering', 'nav-group-dfir'].forEach(groupId => {
        const group = document.getElementById(groupId);
        if (!group) return;
        const menu = group.querySelector('.nav-dropdown-menu');
        if (!menu) return;
        const items = menu.querySelectorAll('li');
        const allHidden = Array.from(items).every(li => li.style.display === 'none');
        group.style.display = allHidden ? 'none' : '';
    });
}

// Nav dropdown — click label navigates, click chevron toggles menu
function toggleNavDropdown(event) {
    const dropdown = event.target.closest('.nav-dropdown');
    if (!dropdown) return;

    // Chevron click = toggle dropdown menu
    if (event.target.closest('.nav-chevron')) {
        event.preventDefault();
        event.stopPropagation();
        document.querySelectorAll('.nav-dropdown.open').forEach(d => {
            if (d !== dropdown) d.classList.remove('open');
        });
        dropdown.classList.toggle('open');
        return;
    }

    // Label click = close any open dropdown and navigate (let <a href> work)
    document.querySelectorAll('.nav-dropdown.open').forEach(d => d.classList.remove('open'));
}

// Close nav dropdowns when clicking outside
document.addEventListener('click', function(e) {
    if (!e.target.closest('.nav-dropdown')) {
        document.querySelectorAll('.nav-dropdown.open').forEach(d => d.classList.remove('open'));
    }
});

async function switchFocusMode(roleName) {
    try {
        const body = roleName ? { role: roleName } : { role: null };
        const resp = await fetch('/api/auth/focus-mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!resp.ok) {
            const err = await resp.json();
            showToast(err.detail || 'Failed to switch focus', 'error');
            return;
        }
        const result = await resp.json();
        // Update cached user data and reload page to apply new view
        currentUserData.focus_role = result.focus_role;
        currentUserData.permissions = result.permissions;
        sessionStorage.setItem('ion_user', JSON.stringify(currentUserData));
        window.location.reload();
    } catch (e) {
        showToast('Failed to switch focus mode', 'error');
    }
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('user-dropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Mobile nav hamburger toggle
function toggleNavMenu() {
    const hamburger = document.getElementById('nav-hamburger');
    const navLinks = document.getElementById('nav-links');
    if (hamburger && navLinks) {
        hamburger.classList.toggle('open');
        navLinks.classList.toggle('mobile-open');
    }
}

// Close dropdown, notification panel, and mobile nav when clicking outside
document.addEventListener('click', function(event) {
    const userMenu = document.getElementById('user-menu');
    const dropdown = document.getElementById('user-dropdown');
    if (userMenu && dropdown && !userMenu.contains(event.target)) {
        dropdown.classList.remove('show');
    }
    // Close notification panel when clicking outside
    const notifBell = document.getElementById('notif-bell-btn');
    const notifPanel = document.getElementById('notif-panel');
    if (notifBell && notifPanel && !notifBell.contains(event.target) && !notifPanel.contains(event.target)) {
        notifPanel.classList.remove('show');
    }
    // Close mobile nav when clicking outside
    const hamburger = document.getElementById('nav-hamburger');
    const navLinks = document.getElementById('nav-links');
    if (hamburger && navLinks && !hamburger.contains(event.target) && !navLinks.contains(event.target)) {
        hamburger.classList.remove('open');
        navLinks.classList.remove('mobile-open');
    }
});

async function logout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (error) {
        // Ignore errors, redirect anyway
    }
    sessionStorage.clear();
    window.location.href = '/login';
}

// =============================================================================
// Notification System
// =============================================================================

let _notifPollInterval = null;
const NOTIF_POLL_MS = 10000;

function toggleNotifPanel() {
    const panel = document.getElementById('notif-panel');
    if (!panel) return;
    const isOpen = panel.classList.toggle('show');
    if (isOpen) {
        loadNotifications();
    }
}

async function loadNotifications() {
    try {
        const data = await api.get('/api/notifications?limit=30');
        renderNotifications(data.notifications || []);
        updateNotifBadge(data.unread_count || 0);
    } catch (e) {
        console.debug('Failed to load notifications:', e);
    }
}

function renderNotifications(notifications) {
    const list = document.getElementById('notif-list');
    if (!list) return;

    if (!notifications.length) {
        list.innerHTML = '<div class="notif-empty">No notifications</div>';
        return;
    }

    const sourceIcons = {
        chat_mention: '@',
        chat_dm: '\u2709',
        chat_group: '\u{1F4AC}',
        case_assigned: '\u26A0',
        gitlab_assigned: '\u{1F4CB}',
        system: '\u2699',
    };

    list.innerHTML = notifications.map(n => {
        const icon = sourceIcons[n.source] || '\u{1F514}';
        const cls = n.is_read ? '' : ' unread';
        const time = n.created_at ? formatNotifTime(n.created_at) : '';
        return `<div class="notif-item${cls}" data-id="${n.id}" data-url="${escapeHtml(n.url || '')}" onclick="handleNotifClick(this)">
            <div class="notif-item-icon">${icon}</div>
            <div class="notif-item-content">
                <div class="notif-item-title">${escapeHtml(n.title)}</div>
                ${n.body ? `<div class="notif-item-body">${escapeHtml(n.body)}</div>` : ''}
                <div class="notif-item-time">${time}</div>
            </div>
        </div>`;
    }).join('');
}

function formatNotifTime(isoString) {
    const d = new Date(isoString);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return diffMin + 'm ago';
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return diffHr + 'h ago';
    const diffDay = Math.floor(diffHr / 24);
    if (diffDay < 7) return diffDay + 'd ago';
    return d.toLocaleDateString();
}

async function handleNotifClick(el) {
    const id = el.dataset.id;
    const url = el.dataset.url;

    // Mark read
    try {
        await api.post('/api/notifications/' + id + '/read');
        el.classList.remove('unread');
        // Decrement badge
        const badge = document.getElementById('notif-unread-badge');
        if (badge) {
            const cur = parseInt(badge.textContent) || 0;
            updateNotifBadge(Math.max(0, cur - 1));
        }
    } catch {}

    // Navigate if URL provided
    if (url && url !== 'null') {
        if (url.startsWith('#chat-room-')) {
            // Open chat to specific room
            const roomId = url.replace('#chat-room-', '');
            if (typeof openChatRoom === 'function') openChatRoom(parseInt(roomId));
        } else {
            window.location.href = url;
        }
    }
}

function updateNotifBadge(count) {
    const badge = document.getElementById('notif-unread-badge');
    const bell = document.getElementById('notif-bell-btn');
    if (badge) {
        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count;
            badge.style.display = 'flex';
            if (bell) bell.classList.add('has-unread');
        } else {
            badge.style.display = 'none';
            if (bell) bell.classList.remove('has-unread');
        }
    }
}

async function markAllNotificationsRead() {
    try {
        await api.post('/api/notifications/read-all');
        updateNotifBadge(0);
        // Re-render the panel
        const list = document.getElementById('notif-list');
        if (list) {
            list.querySelectorAll('.notif-item.unread').forEach(el => el.classList.remove('unread'));
        }
    } catch {}
}

async function pollNotifications() {
    try {
        const data = await api.get('/api/notifications/unread-count');
        updateNotifBadge(data.unread_count || 0);

        // Show toasts for new notifications
        if (data.toasts && data.toasts.length) {
            data.toasts.forEach(t => {
                showToast(t.title + (t.body ? ': ' + t.body.substring(0, 60) : ''), 'info');
            });
        }
    } catch {}
}

function startNotifPolling() {
    if (_notifPollInterval) return;
    // Initial check
    pollNotifications();
    _notifPollInterval = setInterval(pollNotifications, NOTIF_POLL_MS);
}

// Initialize user menu and notifications on page load (if not on login page)
document.addEventListener('DOMContentLoaded', function() {
    if (!window.location.pathname.startsWith('/login')) {
        // Render immediately from cache (no flash)
        if (currentUserData) {
            updateUserMenu();
        }
        // Then refresh from server in background
        loadCurrentUser();
        // Start notification polling
        startNotifPolling();
    }
});
