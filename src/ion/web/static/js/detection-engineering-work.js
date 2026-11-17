/* Work and Bob tabs: requests, proposals, quirks, the content pack, the
   scorecard, disagreements and the abuse monitor. Rows are server-rendered;
   these handlers call /api/de and reload the sub-view that changed. */
(function () {
'use strict';
if (document.body.dataset.page !== 'detection-engineering') return;

const API = '/api/de';
const $ = id => document.getElementById(id);
const toast = (message, kind) => {
    if (typeof window.showToast === 'function') window.showToast(message, kind);
    else if (kind === 'error') alert(message);
};

async function send(method, path, body) {
    const response = await fetch(API + path, {
        method, credentials: 'include', headers: {'Content-Type': 'application/json'},
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || ('HTTP ' + response.status));
    return payload;
}
const post = (path, body) => send('POST', path, body === undefined ? {} : body);

/* Runs a write, reports it, and reloads every sub-view it touched. */
async function act(work, done, failure, subs) {
    try {
        const result = await work();
        if (done) toast(typeof done === 'function' ? done(result) : done, 'success');
        subs.forEach(sub => deReloadSub(sub));
        return result;
    } catch (error) {
        toast(failure + ': ' + error.message, 'error');
        return null;
    }
}

function field(dialog, name) { return dialog.querySelector('[name="' + name + '"]'); }
function value(dialog, name) { return field(dialog, name).value.trim(); }
function csv(text) { return text.split(',').map(s => s.trim()).filter(Boolean); }
function openDialog(id) { const d = $(id); if (d && !d.open) d.showModal(); return d; }
window.dwCloseDialog = function (id) { const d = $(id); if (d && d.open) d.close(); };

/* ── Requests ─────────────────────────────────── */
window.dwTriage = id => act(() => post('/tuning-requests/' + id + '/triage'), 'Request #' + id + ' triaged', 'Triage failed', ['requests']);
window.dwClose = function (id) {
    const resolution = prompt('Resolution (lands on the GitLab ticket):');
    if (resolution === null) return;
    act(() => post('/tuning-requests/' + id + '/close', {resolution: resolution.trim() || 'closed from Detection Engineering'}),
        'Request #' + id + ' closed', 'Close failed', ['requests']);
};
window.dwDraftForRequest = function (id, rule) {
    if (!rule) { toast('This request names no rule to draft against', 'warning'); return; }
    act(async () => {
        const proposal = await post('/proposals', await post('/proposals/draft', {rule_name: rule, days: 90}));
        await post('/tuning-requests/' + id + '/link-proposal', {proposal_id: proposal.id});
        return proposal;
    }, p => 'Draft proposal #' + p.id + ' created for ' + rule + '. Refine it under Proposals.', 'Draft failed', ['requests', 'proposals']);
};

/* ── Proposals ────────────────────────────────── */
/* The filter lives in the page URL, which the shell appends to the
   sub-view's request, so a filtered view can be linked and survives reload. */
window.dwProposalSource = function (source) {
    const params = new URLSearchParams(location.search);
    if (source && source !== 'all') params.set('source', source); else params.delete('source');
    const query = params.toString();
    history.replaceState(null, '', location.pathname + (query ? '?' + query : '') + location.hash);
    deReloadSub('proposals');
};

window.dpEdit = async function (id) {
    let proposal;
    try { proposal = await send('GET', '/proposals/' + id); }
    catch (error) { toast('Could not open the draft: ' + error.message, 'error'); return; }
    const dialog = $('dw-edit-dialog');
    dialog.dataset.id = id;
    dialog.querySelector('[data-field="id"]').textContent = '#' + id;
    for (const name of ['title', 'suggested_change', 'rationale', 'scope']) field(dialog, name).value = proposal[name] || '';
    field(dialog, 'change_type').value = proposal.change_type || 'exclusion';
    openDialog('dw-edit-dialog');
};
window.dwSaveEdit = function () {
    const dialog = $('dw-edit-dialog');
    const id = dialog.dataset.id;
    const body = {};
    for (const name of ['title', 'change_type', 'suggested_change', 'rationale', 'scope']) body[name] = value(dialog, name);
    if (!body.title || !body.suggested_change) { toast('Title and suggested change are required', 'warning'); return; }
    act(() => send('PATCH', '/proposals/' + id, body), 'Proposal #' + id + ' updated', 'Save failed', ['proposals'])
        .then(result => { if (result) dialog.close(); });
};

window.dpDecide = function (id, decision) {
    const dialog = $('dw-decide-dialog');
    dialog.dataset.id = id;
    dialog.dataset.decision = decision;
    dialog.querySelector('[data-field="verb"]').textContent = decision === 'applied' ? 'Apply' : 'Reject';
    dialog.querySelector('[data-field="id"]').textContent = '#' + id;
    dialog.querySelector('[data-applied-only]').hidden = decision !== 'applied';
    field(dialog, 'notes').value = '';
    field(dialog, 'applied_at').value = '';
    openDialog('dw-decide-dialog');
};
window.dwConfirmDecide = function () {
    const dialog = $('dw-decide-dialog');
    const {id, decision} = dialog.dataset;
    const body = {decision, notes: value(dialog, 'notes') || null};
    const date = value(dialog, 'applied_at');
    if (decision === 'applied' && date) body.applied_at = date + 'T00:00:00';
    act(() => post('/proposals/' + id + '/decide', body), 'Proposal #' + id + ' ' + decision, 'Decision failed', ['proposals'])
        .then(result => { if (result) dialog.close(); });
};
window.dpMeasure = id => act(() => post('/proposals/' + id + '/measure-outcome', {days: 30}), outcome => {
    const c = (outcome && outcome.comparable) || {};
    const drop = c.drop_pct === null || c.drop_pct === undefined ? 'no %' : c.drop_pct + '%';
    return 'Measured: ' + drop + ' over matched ' + c.window_days_exact + 'd windows (' + c.before_count + ' → ' + c.after_count + ' FP)';
}, 'Measure failed', ['proposals']);

/* Approval needs an evaluation of this exact text, or a recorded override reason. */
window.bbApprove = function (id, evidenceBacked) {
    const notes = prompt('Approval notes (optional):');
    if (notes === null) return;
    const body = {notes: notes.trim() || null};
    if (!evidenceBacked) {
        const reason = prompt('No evaluation of this text is recorded. Override reason (stored on the proposal):');
        if (!reason || !reason.trim()) return;
        body.override_reason = reason.trim();
    }
    act(() => post('/bob-proposals/' + id + '/approve', body), 'Proposal #' + id + " approved and applied to Bob's prompt",
        'Approve failed', ['proposals', 'scorecard']);
};
window.bbReject = function (id) {
    const notes = prompt('Reject notes (optional):');
    if (notes === null) return;
    act(() => post('/bob-proposals/' + id + '/reject', {notes: notes.trim() || null}), 'Proposal #' + id + ' rejected', 'Reject failed', ['proposals']);
};
window.bbRevert = function (id) {
    if (!confirm("Revert proposal #" + id + " and restore Bob's prior prompt?")) return;
    act(() => post('/bob-proposals/' + id + '/revert'), 'Proposal #' + id + ' reverted', 'Revert failed', ['proposals']);
};

/* ── Quirks ───────────────────────────────────── */
window.dwOpenRaise = function () {
    const dialog = $('dw-raise-dialog');
    dialog.querySelectorAll('input, textarea').forEach(input => { input.value = ''; });
    field(dialog, 'priority_nudge').value = '0';
    openDialog('dw-raise-dialog');
};
window.dwSubmitRaise = function () {
    const dialog = $('dw-raise-dialog');
    const review = value(dialog, 'review_date');
    const body = {
        title: value(dialog, 'title'), annotation: value(dialog, 'annotation'), justification: value(dialog, 'justification'),
        review_date: review ? review + 'T00:00:00' : '',
        priority_nudge: parseInt(value(dialog, 'priority_nudge'), 10) || 0,
        scope_rules: csv(value(dialog, 'scope_rules')), scope_hosts: csv(value(dialog, 'scope_hosts')),
        scope_users: csv(value(dialog, 'scope_users')), scope_ips: csv(value(dialog, 'scope_ips')),
    };
    if (!body.title || !body.annotation || !body.justification) { toast('Title, note and justification are required', 'warning'); return; }
    if (!review) { toast('A review (expiry) date is required', 'warning'); return; }
    act(() => post('/quirks', body), q => 'Quirk #' + q.id + ' raised (pending). A different teammate must verify it.',
        'Raise failed', ['quirks']).then(result => { if (result) dialog.close(); });
};
window.dwVerifyQuirk = id => act(() => post('/quirks/' + id + '/verify'), 'Quirk #' + id + ' verified, now advisory-active', 'Verify failed', ['quirks']);
window.dwRevertQuirk = function (id) {
    const reason = prompt('Revert reason (optional):');
    if (reason === null) return;
    act(() => post('/quirks/' + id + '/revert', {reason}), 'Quirk #' + id + ' reverted', 'Revert failed', ['quirks']);
};

/* ── Content pack ─────────────────────────────── */
window.dwExportPack = function () { location.href = API + '/content-pack/export'; };
window.dwPickPack = function () { const input = $('dw-pack-file'); if (input) input.click(); };
window.dwImportPack = async function (input) {
    const out = $('dw-pack-result');
    const file = input.files && input.files[0];
    input.value = '';
    if (!file) return;
    let pack;
    try { pack = JSON.parse(await file.text()); }
    catch (error) { out.textContent = file.name + ' is not valid JSON.'; return; }
    out.textContent = 'Importing ' + file.name + '...';
    try {
        const d = await post('/content-pack/import', pack);
        const parts = [];
        if (d.quirks_created != null) parts.push('quirks +' + d.quirks_created);
        if (d.proposals_created != null) parts.push('proposals +' + d.proposals_created);
        if (d.errors && d.errors.length) parts.push(d.errors.length + ' error(s)');
        out.textContent = parts.length ? 'Imported: ' + parts.join(', ') : 'Imported. The response reported no counts.';
        deReloadSub('proposals');
        deReloadSub('quirks');
    } catch (error) {
        out.textContent = 'Import failed: ' + error.message;
    }
};

/* ── Bob: draft a tuning proposal from a disagreement class ── */
let bbDraftMeta = null;
window.bbDraft = async function (rule, bobVerdict, humanVerdict) {
    let draft;
    try { draft = await post('/bob-proposals/draft', {rule_name: rule, bob_verdict: bobVerdict, human_verdict: humanVerdict, days: 90}); }
    catch (error) { toast('Draft failed: ' + error.message, 'error'); return; }
    bbDraftMeta = {rule_name: draft.rule_name, template_id: draft.template_id, current_text: draft.current_text,
                   feedback_snapshot: draft.feedback_snapshot};
    const dialog = $('bb-draft-dialog');
    dialog.querySelector('[data-field="problem"]').textContent = draft.problem_statement || '';
    field(dialog, 'title').value = draft.title || '';
    field(dialog, 'problem_statement').value = draft.problem_statement || '';
    field(dialog, 'proposed_text').value = draft.proposed_text || '';
    openDialog('bb-draft-dialog');
};
window.bbSubmitDraft = function () {
    if (!bbDraftMeta) return;
    const dialog = $('bb-draft-dialog');
    const body = Object.assign({}, bbDraftMeta, {
        title: value(dialog, 'title'), proposed_text: value(dialog, 'proposed_text'),
        problem_statement: value(dialog, 'problem_statement') || null,
    });
    if (!body.title || !body.proposed_text) { toast('Title and proposed text are required', 'warning'); return; }
    act(() => post('/bob-proposals', body), p => 'Proposal #' + p.id + ' drafted. A different teammate must approve it.',
        'Create failed', ['proposals']).then(result => { if (result) { dialog.close(); bbDraftMeta = null; } });
};
})();
