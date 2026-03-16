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

async function loadCurrentUser() {
    try {
        const response = await fetch('/api/auth/me');
        if (response.status === 401) {
            // Redirect to login if not authenticated (except on login page)
            if (!window.location.pathname.startsWith('/login')) {
                window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
            }
            return;
        }
        if (response.ok) {
            currentUserData = await response.json();
            updateUserMenu();
        }
    } catch (error) {
        console.error('Error loading user:', error);
    }
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
        if (el) el.style.display = perms.has('security:read') ? 'block' : 'none';
    });

    // Engineer+ links (engineering/admin) — integration & settings access
    ['nav-integrations-link', 'nav-settings-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isEngineer ? 'block' : 'none';
    });

    // Admin only links
    ['nav-admin-links', 'nav-audit-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isAdmin ? 'block' : 'none';
    });

    // Forensics link — only visible when user has forensic:read
    const forensicsLink = document.getElementById('nav-forensics-link');
    if (forensicsLink) {
        forensicsLink.style.display = perms.has('forensic:read') ? 'block' : 'none';
    }
}

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
        // Refresh user data and reload page to apply new view
        currentUserData.focus_role = result.focus_role;
        currentUserData.permissions = result.permissions;
        // Reload to apply dashboard view change
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

// Close dropdown and mobile nav when clicking outside
document.addEventListener('click', function(event) {
    const userMenu = document.getElementById('user-menu');
    const dropdown = document.getElementById('user-dropdown');
    if (userMenu && dropdown && !userMenu.contains(event.target)) {
        dropdown.classList.remove('show');
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
    window.location.href = '/login';
}

// Initialize user menu on page load (if not on login page)
document.addEventListener('DOMContentLoaded', function() {
    if (!window.location.pathname.startsWith('/login')) {
        loadCurrentUser();
    }
});
