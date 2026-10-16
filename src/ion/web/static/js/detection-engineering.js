function cloneTemplate(id) {
    const template = document.getElementById(id);
    return template && template.content.firstElementChild ? template.content.firstElementChild.cloneNode(true) : null;
}

function deMessage(target, message, loading = false) {
    const element = typeof target === 'string' ? document.getElementById(target) : target;
    if (!element) return;
    const node = cloneTemplate(element.tagName === 'SELECT' ? 'de-option-template' : loading ? 'de-loading-template' : 'de-message-template');
    if (loading && element.tagName !== 'SELECT') node.querySelector('[data-loading-message]').textContent = message;
    else node.textContent = message;
    element.replaceChildren(node);
}

const deFragmentRequests = new WeakMap();
async function deLoadFragment(url, targetId, loadingMessage = 'Loading...', options = {}) {
    const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
    if (!target) return false;
    const request = {};
    deFragmentRequests.set(target, request);
    target.setAttribute('hx-sync', 'this:replace');
    deMessage(target, loadingMessage, true);
    let success = false;
    const outcome = event => {
        if (event.detail.target === target) success = event.detail.xhr.status >= 200 && event.detail.xhr.status < 300;
    };
    document.addEventListener('htmx:afterRequest', outcome);
    const showFailure = () => {
        if (deFragmentRequests.get(target) !== request) return;
        if (target.tagName === 'SELECT') deMessage(target, 'Spaces unavailable');
        else if (target.querySelector('[data-loading-message]')) deMessage(target, options.failure || 'Unable to load this panel. Refresh to try again.');
    };
    try {
        await htmx.ajax(options.method || 'GET', url, {target, source:target, swap:'innerHTML', values:options.values});
        if (!success) showFailure();
        return success;
    } catch (error) {
        showFailure();
        return false;
    } finally {
        document.removeEventListener('htmx:afterRequest', outcome);
    }
}

function deSetBadge(message, healthy = false) {
    const node = cloneTemplate('de-badge-template');
    node.querySelector('.de-tide-dot').classList.toggle('ok', healthy);
    node.querySelector('[data-sync-label]').textContent = message;
    document.getElementById('de-tide-badge').replaceChildren(...node.childNodes);
}
