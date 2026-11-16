
function trainingIdentity(value) { return value; }
function trainingMessage(target, message) {
    trainingRender(target, [['open', 'training-node-29', [], false], ['text', message], ['close']]);
}
function trainingJoin(parts, separator) {
    return parts.flatMap((part, index) => index ? [['text', separator], part] : [part]);
}
function trainingRender(target, parts, append = false) {
    if (!target) return;
    const root = document.createDocumentFragment();
    const stack = [root];
    function walk(items) {
        if (items == null || items === false || items === '') return;
        if (!Array.isArray(items)) {
            const text = document.createTextNode('');
            text.textContent = String(items);
            stack[stack.length - 1].appendChild(text);
            return;
        }
        if (typeof items[0] !== 'string' || !['open', 'close', 'text', 'value'].includes(items[0])) {
            items.forEach(walk); return;
        }
        const [kind, value, attributes, empty] = items;
        if (kind === 'close') { if (stack.length > 1) stack.pop(); return; }
        if (kind === 'text' || kind === 'value') { walk(value); return; }
        let element = cloneTemplate(value);
        if (element.tagName.toLowerCase() === 'svg' && element.childElementCount === 1 && value) {
            const template = document.getElementById(value);
            if (template.content.firstElementChild.childElementCount === 1 && !template.content.firstElementChild.hasAttributes()) element = element.firstElementChild;
        }
        attributes.forEach(([name, content]) => {
            if (typeof content === 'boolean') element.toggleAttribute(name, content);
            else element.setAttribute(name, String(content ?? ''));
        });
        stack[stack.length - 1].appendChild(element);
        if (!empty) stack.push(element);
    }
    walk(parts);
    if (append) target.appendChild(root);
    else target.replaceChildren(root);
}
