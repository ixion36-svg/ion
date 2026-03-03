// ION Notepad – slide-out panel with Notes & Clipboard tabs

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────────────
    let quill = null;
    let currentNoteId = null;
    let saveTimer = null;
    const AUTOSAVE_DELAY = 1500; // ms
    const CLIPBOARD_KEY = 'ion-clipboard-items';

    // ── DOM refs (populated on DOMContentLoaded) ──────────────────────
    let panel, overlay;
    let tabNotes, tabClipboard, contentNotes, contentClipboard;
    let noteList, noteEditor, noteSearch, noteTitle, editorContainer;
    let saveStatus;
    let clipList, clipInput;

    // ── Helpers ────────────────────────────────────────────────────────
    function $(sel, ctx) { return (ctx || document).querySelector(sel); }
    function $$(sel, ctx) { return (ctx || document).querySelectorAll(sel); }

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

    // ── Panel toggle ──────────────────────────────────────────────────
    function toggleNotepad() {
        const open = panel.classList.toggle('open');
        overlay.classList.toggle('open', open);
        if (open && !quill) initQuill();
        if (open) loadNotes();
    }

    function closeNotepad() {
        panel.classList.remove('open');
        overlay.classList.remove('open');
    }

    // Expose globally for the navbar button
    window.toggleNotepad = toggleNotepad;

    // ── Tab switching ─────────────────────────────────────────────────
    function switchTab(tab) {
        const isNotes = tab === 'notes';
        tabNotes.classList.toggle('active', isNotes);
        tabClipboard.classList.toggle('active', !isNotes);
        contentNotes.classList.toggle('active', isNotes);
        contentClipboard.classList.toggle('active', !isNotes);
        if (!isNotes) renderClipboard();
    }

    // ════════════════════════════════════════════════════════════════════
    //  NOTES TAB
    // ════════════════════════════════════════════════════════════════════

    // ── Quill init ────────────────────────────────────────────────────
    function initQuill() {
        quill = new Quill('#notepad-editor', {
            theme: 'snow',
            placeholder: 'Start writing...',
            modules: {
                toolbar: [
                    [{ header: [1, 2, 3, false] }],
                    ['bold', 'italic', 'underline', 'strike'],
                    ['code-block', 'blockquote'],
                    [{ list: 'ordered' }, { list: 'bullet' }],
                    ['link'],
                    ['clean'],
                ],
            },
        });

        quill.on('text-change', () => {
            if (currentNoteId) scheduleSave();
        });
    }

    // ── CRUD helpers ──────────────────────────────────────────────────
    async function loadNotes(searchQuery) {
        try {
            const url = searchQuery
                ? `/api/notes/search?q=${encodeURIComponent(searchQuery)}`
                : '/api/notes';
            const notes = await api.get(url);
            renderNoteList(notes);
        } catch (e) {
            console.error('Failed to load notes', e);
        }
    }

    function renderNoteList(notes) {
        if (!notes.length) {
            noteList.innerHTML = '<div class="np-empty">No notes yet</div>';
            return;
        }
        noteList.innerHTML = notes
            .map(
                (n) => `
            <div class="np-note-item${n.id === currentNoteId ? ' active' : ''}" data-id="${n.id}">
                <div class="np-note-item-header">
                    <span class="np-note-title">${escHtml(n.title || 'Untitled')}</span>
                    ${n.is_pinned ? '<span class="np-pin-icon" title="Pinned">&#128204;</span>' : ''}
                </div>
                <span class="np-note-time">${timeAgo(n.updated_at)}</span>
            </div>`
            )
            .join('');

        noteList.querySelectorAll('.np-note-item').forEach((el) => {
            el.addEventListener('click', () => openNote(Number(el.dataset.id)));
        });
    }

    async function createNote() {
        try {
            const note = await api.post('/api/notes', { title: 'Untitled' });
            await loadNotes();
            openNote(note.id);
        } catch (e) {
            console.error('Failed to create note', e);
        }
    }

    async function openNote(id) {
        try {
            const note = await api.get(`/api/notes/${id}`);
            currentNoteId = note.id;
            noteTitle.value = note.title || '';
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
            setSaveStatus('');
            // highlight in list
            noteList.querySelectorAll('.np-note-item').forEach((el) => {
                el.classList.toggle('active', Number(el.dataset.id) === id);
            });
        } catch (e) {
            console.error('Failed to open note', e);
        }
    }

    function showEditor(show) {
        noteEditor.style.display = show ? 'flex' : 'none';
        noteList.style.display = show ? 'none' : '';
        $('.np-list-header', contentNotes).style.display = show ? 'none' : '';
    }

    function backToList() {
        flushSave();
        currentNoteId = null;
        showEditor(false);
        loadNotes();
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
        try {
            const delta = JSON.stringify(quill.getContents());
            const html = quill.root.innerHTML;
            await api.put(`/api/notes/${currentNoteId}`, {
                title: noteTitle.value || 'Untitled',
                content: delta,
                content_html: html,
            });
            setSaveStatus('Saved');
        } catch (e) {
            setSaveStatus('Error');
            console.error('Auto-save failed', e);
        }
    }

    function setSaveStatus(text) {
        if (saveStatus) saveStatus.textContent = text;
    }

    // ── Pin / Delete ──────────────────────────────────────────────────
    async function pinCurrentNote() {
        if (!currentNoteId) return;
        try {
            await api.post(`/api/notes/${currentNoteId}/pin`);
        } catch (e) {
            console.error('Pin failed', e);
        }
    }

    async function deleteCurrentNote() {
        if (!currentNoteId) return;
        if (!confirm('Delete this note?')) return;
        try {
            await api.delete(`/api/notes/${currentNoteId}`);
            backToList();
        } catch (e) {
            console.error('Delete failed', e);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  CLIPBOARD TAB
    // ════════════════════════════════════════════════════════════════════

    function getClipItems() {
        try {
            return JSON.parse(localStorage.getItem(CLIPBOARD_KEY) || '[]');
        } catch {
            return [];
        }
    }

    function setClipItems(items) {
        localStorage.setItem(CLIPBOARD_KEY, JSON.stringify(items));
    }

    function renderClipboard() {
        const items = getClipItems();
        if (!items.length) {
            clipList.innerHTML = '<div class="np-empty">Clipboard is empty</div>';
            return;
        }
        clipList.innerHTML = items
            .map(
                (text, i) => `
            <div class="np-clip-item">
                <span class="np-clip-text">${escHtml(text)}</span>
                <div class="np-clip-actions">
                    <button class="np-btn-xs" data-copy="${i}" title="Copy">&#128203;</button>
                    <button class="np-btn-xs np-btn-danger" data-remove="${i}" title="Remove">&times;</button>
                </div>
            </div>`
            )
            .join('');

        clipList.querySelectorAll('[data-copy]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const idx = Number(btn.dataset.copy);
                const items = getClipItems();
                navigator.clipboard.writeText(items[idx]).then(() => {
                    btn.textContent = '\u2713';
                    setTimeout(() => (btn.textContent = '\uD83D\uDCCB'), 1000);
                });
            });
        });

        clipList.querySelectorAll('[data-remove]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const idx = Number(btn.dataset.remove);
                const items = getClipItems();
                items.splice(idx, 1);
                setClipItems(items);
                renderClipboard();
            });
        });
    }

    function addClipItem() {
        const text = clipInput.value.trim();
        if (!text) return;
        const items = getClipItems();
        items.unshift(text);
        setClipItems(items);
        clipInput.value = '';
        renderClipboard();
    }

    function clearClipboard() {
        if (!confirm('Clear all clipboard items?')) return;
        setClipItems([]);
        renderClipboard();
    }

    // ════════════════════════════════════════════════════════════════════
    //  INIT
    // ════════════════════════════════════════════════════════════════════

    document.addEventListener('DOMContentLoaded', () => {
        panel = $('#notepad-panel');
        overlay = $('#notepad-overlay');
        if (!panel) return; // guard if template not loaded

        tabNotes = $('#np-tab-notes');
        tabClipboard = $('#np-tab-clipboard');
        contentNotes = $('#np-content-notes');
        contentClipboard = $('#np-content-clipboard');

        noteList = $('#np-note-list');
        noteEditor = $('#np-note-editor');
        noteSearch = $('#np-search');
        noteTitle = $('#np-note-title');
        editorContainer = $('#notepad-editor');
        saveStatus = $('#np-save-status');

        clipList = $('#np-clip-list');
        clipInput = $('#np-clip-input');

        // Tabs
        tabNotes.addEventListener('click', () => switchTab('notes'));
        tabClipboard.addEventListener('click', () => switchTab('clipboard'));

        // Note list header buttons
        $('#np-btn-new').addEventListener('click', createNote);

        // Search
        let searchTimer;
        noteSearch.addEventListener('input', () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
                const q = noteSearch.value.trim();
                loadNotes(q || undefined);
            }, 300);
        });

        // Editor toolbar buttons
        $('#np-btn-back').addEventListener('click', backToList);
        $('#np-btn-pin').addEventListener('click', pinCurrentNote);
        $('#np-btn-delete').addEventListener('click', deleteCurrentNote);

        // Title auto-save
        noteTitle.addEventListener('input', () => {
            if (currentNoteId) scheduleSave();
        });

        // Clipboard
        $('#np-btn-add-clip').addEventListener('click', addClipItem);
        $('#np-btn-clear-clip').addEventListener('click', clearClipboard);
        clipInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') addClipItem();
        });

        // Overlay close
        overlay.addEventListener('click', closeNotepad);

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+Shift+N toggle
            if (e.ctrlKey && e.shiftKey && e.key === 'N') {
                e.preventDefault();
                toggleNotepad();
            }
            // Escape close
            if (e.key === 'Escape' && panel.classList.contains('open')) {
                closeNotepad();
            }
        });
    });
})();
