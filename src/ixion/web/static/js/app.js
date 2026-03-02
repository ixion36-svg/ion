// IXION Web UI JavaScript

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
        dropdownHeader.innerHTML = `
            <div class="dropdown-user-info">
                <strong>${escapeHtml(currentUserData.display_name || currentUserData.username)}</strong>
                <span class="dropdown-email">${escapeHtml(currentUserData.email)}</span>
            </div>
            <div class="dropdown-roles">${roles}</div>
        `;
    }

    // Role-based nav visibility: 4-tier hierarchy
    const roles = currentUserData.roles;
    const isAnalyst = ['analyst', 'lead', 'engineering', 'admin'].some(r => roles.includes(r));
    const isLead = ['lead', 'engineering', 'admin'].some(r => roles.includes(r));
    const isEngineer = ['engineering', 'admin'].some(r => roles.includes(r));
    const isAdmin = roles.includes('admin');

    // Analyst+ links (analyst/lead/engineering/admin)
    ['nav-alerts-link', 'nav-cases-link', 'nav-observables-link', 'nav-playbooks-link', 'nav-training-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isAnalyst ? 'block' : 'none';
    });

    // Lead+ links (lead/engineering/admin) - security read access
    const securityLink = document.getElementById('nav-security-link');
    if (securityLink) securityLink.style.display = isLead ? 'block' : 'none';

    // Engineer+ links (engineering/admin)
    ['nav-integrations-link', 'nav-settings-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isEngineer ? 'block' : 'none';
    });

    // Admin only links
    ['nav-admin-links', 'nav-audit-link'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isAdmin ? 'block' : 'none';
    });
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('user-dropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const userMenu = document.getElementById('user-menu');
    const dropdown = document.getElementById('user-dropdown');
    if (userMenu && dropdown && !userMenu.contains(event.target)) {
        dropdown.classList.remove('show');
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
