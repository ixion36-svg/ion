// ION Notes – Full-page dedicated notes view
// Separate from notepad.js (sidebar) to avoid conflicts

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────────────
    let quill = null;
    let currentNoteId = null;
    let currentNote = null;
    let saveTimer = null;
    let hasUnsavedChanges = false;
    const AUTOSAVE_DELAY = 1500;

    // Folder state
    let folderTree = [];
    let selectedFolderId = null; // null = "All Notes", 'uncategorized' = no folder
    let expandedFolders = {};

    const STORAGE_KEY = 'ion-notes-folder-state';

    const NOTE_COLORS = [
        { value: null, label: 'None', hex: 'transparent' },
        { value: 'red', label: 'Red', hex: '#f85149' },
        { value: 'orange', label: 'Orange', hex: '#d29922' },
        { value: 'yellow', label: 'Yellow', hex: '#e3b341' },
        { value: 'green', label: 'Green', hex: '#3fb950' },
        { value: 'blue', label: 'Blue', hex: '#58a6ff' },
        { value: 'purple', label: 'Purple', hex: '#bc8cff' },
        { value: 'pink', label: 'Pink', hex: '#f778ba' },
    ];

    // ── DOM refs ──────────────────────────────────────────────────────
    let notesList, searchInput, titleInput, saveStatus;
    let editorPlaceholder, editorWrapper;
    let colorBtn, colorDot, colorDropdown;
    let pinBtn, deleteBtn, moveBtn;
    let folderListEl, moveDropdown;

    // ── Helpers ────────────────────────────────────────────────────────
    function escHtml(s) {
        if (!s) return '';
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function timeAgo(iso) {
        if (!iso) return '';
        const diff = Date.now() - new Date(iso).getTime();
        const m = Math.floor(diff / 60000);
        if (m < 1) return 'just now';
        if (m < 60) return m + 'm ago';
        const h = Math.floor(m / 60);
        if (h < 24) return h + 'h ago';
        const d = Math.floor(h / 24);
        return d + 'd ago';
    }

    function stripHtml(html) {
        if (!html) return '';
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        return (tmp.textContent || tmp.innerText || '').substring(0, 120);
    }

    function getColorHex(colorValue) {
        const c = NOTE_COLORS.find(c => c.value === colorValue);
        return c ? c.hex : 'transparent';
    }

    function loadExpandedState() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) expandedFolders = JSON.parse(raw);
        } catch { expandedFolders = {}; }
    }

    function saveExpandedState() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(expandedFolders));
        } catch { /* ignore */ }
    }

    // ── Quill init ────────────────────────────────────────────────────
    function initQuill() {
        quill = new Quill('#fp-quill-editor', {
            theme: 'snow',
            placeholder: 'Start writing...',
            modules: {
                toolbar: [
                    [{ header: [1, 2, 3, false] }],
                    [{ font: [] }],
                    ['bold', 'italic', 'underline', 'strike'],
                    [{ color: [] }, { background: [] }],
                    ['code-block', 'blockquote'],
                    [{ list: 'ordered' }, { list: 'bullet' }, { list: 'check' }],
                    [{ indent: '-1' }, { indent: '+1' }],
                    [{ align: [] }],
                    ['link', 'image'],
                    ['clean'],
                ],
            },
        });

        quill.on('text-change', () => {
            if (currentNoteId) {
                hasUnsavedChanges = true;
                scheduleSave();
            }
        });
    }

    // ── Folder tree ───────────────────────────────────────────────────
    async function loadFolders() {
        try {
            folderTree = await api.get('/api/notes/folders');
            renderFolderTree();
        } catch (e) {
            console.error('Failed to load folders', e);
        }
    }

    function flattenTree(nodes, depth, result) {
        for (const node of nodes) {
            result.push({ ...node, depth });
            if (node.children && node.children.length) {
                flattenTree(node.children, depth + 1, result);
            }
        }
        return result;
    }

    function renderFolderTree() {
        const flat = flattenTree(folderTree, 0, []);
        let html = '';

        // "All Notes" virtual folder
        html += `<div class="folder-item${selectedFolderId === null ? ' active' : ''}" data-folder="all" data-depth="0">
            <span class="folder-expand empty"></span>
            <span class="folder-icon">&#128209;</span>
            <span class="folder-name">All Notes</span>
        </div>`;

        // User folders
        for (const f of flat) {
            const hasChildren = f.children && f.children.length > 0;
            const isExpanded = !!expandedFolders[f.id];
            const isActive = selectedFolderId === f.id;
            const isHidden = !isFolderVisible(f, flat);

            html += `<div class="folder-item${isActive ? ' active' : ''}" data-folder="${f.id}" data-depth="${f.depth}" ${isHidden ? 'style="display:none"' : ''}>
                <span class="folder-expand${hasChildren ? (isExpanded ? ' expanded' : '') : ' empty'}" data-toggle="${f.id}">&#9654;</span>
                <span class="folder-icon">${f.icon || '&#128193;'}</span>
                <span class="folder-name">${escHtml(f.name)}</span>
                <span class="folder-count">${f.notes_count || ''}</span>
                <span class="folder-actions">
                    <button data-folder-add="${f.id}" title="Add sub-folder">+</button>
                    <button data-folder-rename="${f.id}" title="Rename">&#9998;</button>
                    <button data-folder-delete="${f.id}" title="Delete" class="danger">&times;</button>
                </span>
            </div>`;
        }

        // "Uncategorized" virtual folder
        html += `<div class="folder-item${selectedFolderId === 'uncategorized' ? ' active' : ''}" data-folder="uncategorized" data-depth="0">
            <span class="folder-expand empty"></span>
            <span class="folder-icon">&#128196;</span>
            <span class="folder-name">Uncategorized</span>
        </div>`;

        folderListEl.innerHTML = html;
        bindFolderEvents();
    }

    function isFolderVisible(folder, flat) {
        if (folder.depth === 0) return true;
        let parentId = folder.parent_id;
        while (parentId) {
            if (!expandedFolders[parentId]) return false;
            const parent = flat.find(f => f.id === parentId);
            if (!parent) break;
            parentId = parent.parent_id;
        }
        return true;
    }

    function bindFolderEvents() {
        // Click to select folder
        folderListEl.querySelectorAll('.folder-item').forEach(el => {
            el.addEventListener('click', (e) => {
                if (e.target.closest('.folder-actions') || e.target.closest('.folder-expand:not(.empty)')) return;
                const fid = el.dataset.folder;
                if (fid === 'all') selectedFolderId = null;
                else if (fid === 'uncategorized') selectedFolderId = 'uncategorized';
                else selectedFolderId = Number(fid);
                renderFolderTree();
                loadNotes(searchInput.value.trim() || undefined);
            });
        });

        // Toggle expand/collapse
        folderListEl.querySelectorAll('.folder-expand:not(.empty)').forEach(el => {
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                const fid = Number(el.dataset.toggle);
                expandedFolders[fid] = !expandedFolders[fid];
                saveExpandedState();
                renderFolderTree();
            });
        });

        // Add sub-folder
        folderListEl.querySelectorAll('[data-folder-add]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const parentId = Number(btn.dataset.folderAdd);
                promptNewFolder(parentId);
            });
        });

        // Rename folder
        folderListEl.querySelectorAll('[data-folder-rename]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const folderId = Number(btn.dataset.folderRename);
                startInlineRename(folderId);
            });
        });

        // Delete folder
        folderListEl.querySelectorAll('[data-folder-delete]').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const folderId = Number(btn.dataset.folderDelete);
                if (!confirm('Delete this folder? Notes in it will be moved to Uncategorized.')) return;
                try {
                    await api.delete(`/api/notes/folders/${folderId}`);
                    if (selectedFolderId === folderId) selectedFolderId = null;
                    await loadFolders();
                    await loadNotes(searchInput.value.trim() || undefined);
                } catch (err) {
                    console.error('Delete folder failed', err);
                }
            });
        });

        // Drag-and-drop: folders as drop targets
        folderListEl.querySelectorAll('.folder-item').forEach(el => {
            el.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                el.classList.add('drop-target');
            });
            el.addEventListener('dragenter', (e) => {
                e.preventDefault();
                el.classList.add('drop-target');
            });
            el.addEventListener('dragleave', (e) => {
                // Only remove if we actually left this element (not entering a child)
                if (!el.contains(e.relatedTarget)) {
                    el.classList.remove('drop-target');
                }
            });
            el.addEventListener('drop', async (e) => {
                e.preventDefault();
                el.classList.remove('drop-target');
                const noteId = e.dataTransfer.getData('text/plain');
                if (!noteId) return;

                const fid = el.dataset.folder;
                let targetFolderId = null;
                if (fid === 'all') targetFolderId = null;
                else if (fid === 'uncategorized') targetFolderId = null;
                else targetFolderId = Number(fid);

                try {
                    await api.put(`/api/notes/${noteId}/move`, { folder_id: targetFolderId });
                    await loadFolders();
                    await loadNotes(searchInput.value.trim() || undefined);
                } catch (err) {
                    console.error('Drag-move failed', err);
                }
            });
        });
    }

    async function promptNewFolder(parentId) {
        const name = prompt('Folder name:');
        if (!name || !name.trim()) return;
        try {
            await api.post('/api/notes/folders', {
                name: name.trim(),
                parent_id: parentId || null,
            });
            if (parentId) {
                expandedFolders[parentId] = true;
                saveExpandedState();
            }
            await loadFolders();
        } catch (e) {
            console.error('Create folder failed', e);
        }
    }

    function startInlineRename(folderId) {
        const item = folderListEl.querySelector(`[data-folder="${folderId}"]`);
        if (!item) return;
        const nameEl = item.querySelector('.folder-name');
        const oldName = nameEl.textContent;

        const input = document.createElement('input');
        input.className = 'folder-rename-input';
        input.value = oldName;
        nameEl.replaceWith(input);
        input.focus();
        input.select();

        async function commit() {
            const newName = input.value.trim();
            if (newName && newName !== oldName) {
                try {
                    await api.put(`/api/notes/folders/${folderId}`, { name: newName });
                } catch (err) {
                    console.error('Rename failed', err);
                }
            }
            await loadFolders();
        }

        input.addEventListener('blur', commit);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = oldName; input.blur(); }
        });
    }

    // ── Note list ─────────────────────────────────────────────────────
    async function loadNotes(searchQuery) {
        try {
            let url;
            if (searchQuery) {
                url = `/api/notes/search?q=${encodeURIComponent(searchQuery)}`;
                if (selectedFolderId !== null && selectedFolderId !== 'uncategorized') {
                    url += `&folder_id=${selectedFolderId}`;
                }
            } else if (selectedFolderId === 'uncategorized') {
                url = '/api/notes?uncategorized=true';
            } else if (selectedFolderId !== null) {
                url = `/api/notes?folder_id=${selectedFolderId}`;
            } else {
                url = '/api/notes';
            }
            const notes = await api.get(url);
            renderNoteList(notes);
        } catch (e) {
            console.error('Failed to load notes', e);
        }
    }

    function renderNoteList(notes) {
        if (!notes.length) {
            notesList.innerHTML = '<div class="notes-empty">No notes yet. Click "+ New Note" to start.</div>';
            return;
        }

        notesList.innerHTML = notes.map(n => {
            const preview = stripHtml(n.content_html);
            const colorHex = getColorHex(n.color);
            return `
            <div class="note-card${n.id === currentNoteId ? ' active' : ''}" data-id="${n.id}" draggable="true">
                <div class="note-card-header">
                    <span class="note-card-title">${escHtml(n.title || 'Untitled')}</span>
                    ${n.is_pinned ? '<span class="note-card-pin" title="Pinned">&#128204;</span>' : ''}
                </div>
                ${preview ? `<div class="note-card-preview">${escHtml(preview)}</div>` : ''}
                <div class="note-card-meta">
                    <span class="note-card-time">${timeAgo(n.updated_at)}</span>
                    <div style="display:flex;align-items:center;gap:6px">
                        ${n.color ? `<span class="note-card-color" style="background:${colorHex}"></span>` : ''}
                        <div class="note-card-actions">
                            <button class="note-card-btn" data-pin="${n.id}" title="${n.is_pinned ? 'Unpin' : 'Pin'}">&#128204;</button>
                            <button class="note-card-btn danger" data-del="${n.id}" title="Delete">&times;</button>
                        </div>
                    </div>
                </div>
            </div>`;
        }).join('');

        // Click to open
        notesList.querySelectorAll('.note-card').forEach(el => {
            el.addEventListener('click', (e) => {
                if (e.target.closest('[data-pin]') || e.target.closest('[data-del]')) return;
                openNote(Number(el.dataset.id));
            });
        });

        // Pin buttons in list
        notesList.querySelectorAll('[data-pin]').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const id = Number(btn.dataset.pin);
                try {
                    await api.post(`/api/notes/${id}/pin`);
                    await loadNotes(searchInput.value.trim() || undefined);
                    if (currentNoteId === id) {
                        currentNote.is_pinned = !currentNote.is_pinned;
                        updatePinButton();
                    }
                } catch (err) {
                    console.error('Pin failed', err);
                }
            });
        });

        // Delete buttons in list
        notesList.querySelectorAll('[data-del]').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const id = Number(btn.dataset.del);
                if (!confirm('Delete this note?')) return;
                try {
                    await api.delete(`/api/notes/${id}`);
                    if (currentNoteId === id) {
                        currentNoteId = null;
                        currentNote = null;
                        hasUnsavedChanges = false;
                        showEditor(false);
                    }
                    await loadNotes(searchInput.value.trim() || undefined);
                    await loadFolders();
                } catch (err) {
                    console.error('Delete failed', err);
                }
            });
        });

        // Drag start on note cards
        notesList.querySelectorAll('.note-card[draggable]').forEach(el => {
            el.addEventListener('dragstart', (e) => {
                e.dataTransfer.setData('text/plain', el.dataset.id);
                e.dataTransfer.effectAllowed = 'move';
                el.classList.add('dragging');
            });
            el.addEventListener('dragend', () => {
                el.classList.remove('dragging');
                // Clear all drop highlights
                folderListEl.querySelectorAll('.folder-item').forEach(f => f.classList.remove('drop-target'));
            });
        });
    }

    // ── Create note ───────────────────────────────────────────────────
    async function createNote() {
        try {
            const folderId = (selectedFolderId !== null && selectedFolderId !== 'uncategorized')
                ? selectedFolderId : null;
            const note = await api.post('/api/notes', {
                title: 'Untitled',
                folder_id: folderId,
            });
            await loadFolders();
            await loadNotes();
            openNote(note.id);
        } catch (e) {
            console.error('Failed to create note', e);
        }
    }

    // ── Open note ─────────────────────────────────────────────────────
    async function openNote(id) {
        if (currentNoteId && hasUnsavedChanges) {
            await doSave();
        }

        try {
            const note = await api.get(`/api/notes/${id}`);
            currentNoteId = note.id;
            currentNote = note;
            hasUnsavedChanges = false;

            titleInput.value = note.title || '';
            if (quill) {
                if (note.content) {
                    try {
                        quill.setContents(JSON.parse(note.content));
                    } catch {
                        quill.root.innerHTML = note.content_html || '';
                    }
                } else {
                    quill.setContents([{ insert: '\n' }]);
                }
            }

            showEditor(true);
            updatePinButton();
            updateColorDot();
            setSaveStatus('');

            notesList.querySelectorAll('.note-card').forEach(el => {
                el.classList.toggle('active', Number(el.dataset.id) === id);
            });
        } catch (e) {
            console.error('Failed to open note', e);
        }
    }

    function showEditor(show) {
        editorPlaceholder.style.display = show ? 'none' : 'flex';
        editorWrapper.style.display = show ? 'flex' : 'none';
        if (show) {
            editorWrapper.style.flexDirection = 'column';
            editorWrapper.style.flex = '1';
        }
    }

    // ── Auto-save ─────────────────────────────────────────────────────
    function scheduleSave() {
        clearTimeout(saveTimer);
        setSaveStatus('Saving...');
        saveTimer = setTimeout(doSave, AUTOSAVE_DELAY);
    }

    function flushSave() {
        if (saveTimer) {
            clearTimeout(saveTimer);
            saveTimer = null;
            doSave();
        }
    }

    async function doSave() {
        if (!currentNoteId || !quill) return;
        saveTimer = null;
        try {
            const delta = JSON.stringify(quill.getContents());
            const html = quill.root.innerHTML;
            await api.put(`/api/notes/${currentNoteId}`, {
                title: titleInput.value || 'Untitled',
                content: delta,
                content_html: html,
            });
            hasUnsavedChanges = false;
            setSaveStatus('Saved');
        } catch (e) {
            setSaveStatus('Error saving');
            console.error('Auto-save failed', e);
        }
    }

    function setSaveStatus(text) {
        if (saveStatus) saveStatus.textContent = text;
    }

    // ── Pin / Delete (editor actions) ─────────────────────────────────
    async function togglePin() {
        if (!currentNoteId) return;
        try {
            const updated = await api.post(`/api/notes/${currentNoteId}/pin`);
            currentNote.is_pinned = updated.is_pinned;
            updatePinButton();
            await loadNotes(searchInput.value.trim() || undefined);
        } catch (e) {
            console.error('Pin failed', e);
        }
    }

    function updatePinButton() {
        if (!currentNote) return;
        pinBtn.classList.toggle('pinned', !!currentNote.is_pinned);
        pinBtn.title = currentNote.is_pinned ? 'Unpin' : 'Pin';
    }

    async function deleteNote() {
        if (!currentNoteId) return;
        if (!confirm('Delete this note?')) return;
        try {
            await api.delete(`/api/notes/${currentNoteId}`);
            currentNoteId = null;
            currentNote = null;
            hasUnsavedChanges = false;
            showEditor(false);
            await loadNotes(searchInput.value.trim() || undefined);
            await loadFolders();
        } catch (e) {
            console.error('Delete failed', e);
        }
    }

    // ── Move to folder ────────────────────────────────────────────────
    function showMoveDropdown() {
        if (!currentNoteId) return;

        const allFolders = flattenTree(folderTree, 0, []);
        let html = `<div class="move-folder-option" data-move-to="null">Uncategorized</div>`;
        for (const f of allFolders) {
            const indent = '\u00A0\u00A0'.repeat(f.depth);
            const icon = f.icon || '&#128193;';
            html += `<div class="move-folder-option" data-move-to="${f.id}">${indent}${icon} ${escHtml(f.name)}</div>`;
        }
        moveDropdown.innerHTML = html;

        const rect = moveBtn.getBoundingClientRect();
        moveDropdown.style.position = 'fixed';
        moveDropdown.style.top = (rect.bottom + 4) + 'px';
        moveDropdown.style.left = rect.left + 'px';
        moveDropdown.classList.add('open');

        moveDropdown.querySelectorAll('.move-folder-option').forEach(opt => {
            opt.addEventListener('click', async () => {
                const targetId = opt.dataset.moveTo === 'null' ? null : Number(opt.dataset.moveTo);
                moveDropdown.classList.remove('open');
                try {
                    await api.put(`/api/notes/${currentNoteId}/move`, { folder_id: targetId });
                    currentNote.folder_id = targetId;
                    await loadFolders();
                    await loadNotes(searchInput.value.trim() || undefined);
                } catch (err) {
                    console.error('Move failed', err);
                }
            });
        });
    }

    // ── Color picker ──────────────────────────────────────────────────
    function initColorPicker() {
        colorDropdown.innerHTML = NOTE_COLORS.map(c => `
            <span class="notes-color-option${!c.value ? ' active' : ''}"
                  data-color="${c.value || ''}"
                  title="${c.label}"
                  style="background:${c.hex};${!c.value ? 'background:var(--bg-secondary,#161b22);border:1px dashed var(--border-color,#30363d)' : ''}">
            </span>
        `).join('');

        colorDropdown.querySelectorAll('.notes-color-option').forEach(opt => {
            opt.addEventListener('click', async () => {
                const colorVal = opt.dataset.color || null;
                if (!currentNoteId) return;
                try {
                    await api.put(`/api/notes/${currentNoteId}`, { color: colorVal });
                    currentNote.color = colorVal;
                    updateColorDot();
                    colorDropdown.classList.remove('open');
                    await loadNotes(searchInput.value.trim() || undefined);
                } catch (e) {
                    console.error('Color change failed', e);
                }
            });
        });

        colorBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            colorDropdown.classList.toggle('open');
            moveDropdown.classList.remove('open');
        });

        document.addEventListener('click', () => {
            colorDropdown.classList.remove('open');
            moveDropdown.classList.remove('open');
        });
        colorDropdown.addEventListener('click', (e) => e.stopPropagation());
        moveDropdown.addEventListener('click', (e) => e.stopPropagation());
    }

    function updateColorDot() {
        if (!currentNote) return;
        const hex = getColorHex(currentNote.color);
        if (currentNote.color) {
            colorDot.style.background = hex;
            colorDot.style.border = 'none';
        } else {
            colorDot.style.background = 'transparent';
            colorDot.style.border = '1px solid var(--border-color, #30363d)';
        }
        colorDropdown.querySelectorAll('.notes-color-option').forEach(opt => {
            opt.classList.toggle('active', (opt.dataset.color || null) === (currentNote.color || null));
        });
    }

    // ── Keyboard shortcuts ────────────────────────────────────────────
    function handleKeyboard(e) {
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            if (currentNoteId) {
                clearTimeout(saveTimer);
                doSave();
            }
        }
        if (e.ctrlKey && e.key === 'n') {
            if (document.activeElement.tagName !== 'INPUT') {
                e.preventDefault();
                createNote();
            }
        }
    }

    // ── Unsaved changes guard ─────────────────────────────────────────
    function beforeUnloadHandler(e) {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = '';
        }
    }

    // ── Init ──────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        const page = document.querySelector('.notes-page');
        if (!page) return;

        notesList = document.getElementById('fp-notes-list');
        searchInput = document.getElementById('fp-notes-search');
        titleInput = document.getElementById('fp-note-title');
        saveStatus = document.getElementById('fp-save-status');
        editorPlaceholder = document.getElementById('fp-editor-placeholder');
        editorWrapper = document.getElementById('fp-editor-wrapper');
        colorBtn = document.getElementById('fp-color-btn');
        colorDot = document.getElementById('fp-color-dot');
        colorDropdown = document.getElementById('fp-color-dropdown');
        pinBtn = document.getElementById('fp-btn-pin');
        deleteBtn = document.getElementById('fp-btn-delete');
        moveBtn = document.getElementById('fp-btn-move');
        folderListEl = document.getElementById('fp-folder-list');
        moveDropdown = document.getElementById('fp-move-dropdown');

        loadExpandedState();
        initQuill();
        initColorPicker();
        loadFolders();
        loadNotes();

        document.getElementById('fp-notes-new').addEventListener('click', createNote);

        document.getElementById('fp-folder-add').addEventListener('click', () => {
            promptNewFolder(null);
        });

        moveBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            colorDropdown.classList.remove('open');
            showMoveDropdown();
        });

        let searchTimer;
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
                loadNotes(searchInput.value.trim() || undefined);
            }, 300);
        });

        titleInput.addEventListener('input', () => {
            if (currentNoteId) {
                hasUnsavedChanges = true;
                scheduleSave();
            }
        });

        pinBtn.addEventListener('click', togglePin);
        deleteBtn.addEventListener('click', deleteNote);
        document.addEventListener('keydown', handleKeyboard);
        window.addEventListener('beforeunload', beforeUnloadHandler);
    });
})();
