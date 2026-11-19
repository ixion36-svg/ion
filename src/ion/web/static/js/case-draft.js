/* The prefilled title, description and evidence for a case made from alerts.
 *
 * The title is deterministic: it says how many alerts and where, never which
 * rule fired last, so the same selection always gets the same title.
 *   1 host   -> "Investigation: 30 alerts on WS-01"
 *   n hosts  -> "Investigation: 30 alerts across 3 hosts"
 *   no host  -> "Investigation: 30 alerts for j.doe" (one user) or "Investigation: 30 alerts"
 *
 * Loaded by alerts.html; exported for node so tests can call it directly.
 */
(function (root) {
    'use strict';

    const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
    const LIST_CAP = 10;

    function uniq(values) {
        return [...new Set(values.filter((v) => v !== null && v !== undefined && v !== ''))]
            .map(String).sort((a, b) => a.localeCompare(b));
    }

    function capped(values) {
        if (values.length <= LIST_CAP) return values.join(', ');
        return values.slice(0, LIST_CAP).join(', ') + ` (+${values.length - LIST_CAP} more)`;
    }

    function plural(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}`; }

    // A raw alert may be flat ("kibana.alert.rule.name"), nested, or both
    // ({"kibana.alert.rule.parameters": {"investigation_fields": ...}}), so
    // each step tries the longest dotted key first.
    function dig(obj, path) {
        if (!obj || typeof obj !== 'object') return undefined;
        if (path in obj) return obj[path];
        const parts = path.split('.');
        for (let i = parts.length - 1; i >= 1; i--) {
            const head = parts.slice(0, i).join('.');
            if (head in obj) {
                const found = dig(obj[head], parts.slice(i).join('.'));
                if (found !== undefined) return found;
            }
        }
        return undefined;
    }

    function utc(ms) {
        return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
    }

    function span(ms) {
        const s = Math.round(ms / 1000);
        const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
            m = Math.floor(s % 3600 / 60), sec = s % 60;
        return [d && `${d}d`, h && `${h}h`, m && `${m}m`, `${sec}s`].filter(Boolean).join(' ');
    }

    function counted(values) {
        const m = new Map();
        values.filter(Boolean).forEach((v) => m.set(v, (m.get(v) || 0) + 1));
        return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
            .map(([v, n]) => (n > 1 ? `${v} ×${n}` : v));
    }

    function highestSeverity(alerts) {
        const present = new Set(alerts.map((a) => a.severity));
        return SEV_ORDER.find((s) => present.has(s)) || '';
    }

    function title(alerts) {
        const volume = plural(alerts.length, 'alert');
        const hosts = uniq(alerts.map((a) => a.host));
        if (hosts.length === 1) return `Investigation: ${volume} on ${hosts[0]}`;
        if (hosts.length > 1) return `Investigation: ${volume} across ${hosts.length} hosts`;
        const users = uniq(alerts.map((a) => a.user));
        if (users.length === 1) return `Investigation: ${volume} for ${users[0]}`;
        return `Investigation: ${volume}`;
    }

    // The fields the rule author marked as highlighted, with the values the
    // selected alerts carry for them.
    function highlighted(alerts) {
        const byField = new Map();
        alerts.forEach((a) => {
            const raw = a.raw_data;
            const names = dig(raw, 'kibana.alert.rule.parameters.investigation_fields.field_names')
                || dig(raw, 'kibana.alert.rule.investigation_fields.field_names') || [];
            (Array.isArray(names) ? names : []).forEach((f) => {
                const v = dig(raw, f);
                if (v === undefined || v === null || typeof v === 'object') return;
                if (!byField.has(f)) byField.set(f, []);
                byField.get(f).push(v);
            });
        });
        return [...byField.entries()].sort((a, b) => a[0].localeCompare(b[0]))
            .map(([f, vs]) => `  ${f}: ${capped(uniq(vs))}`);
    }

    function build(alerts) {
        alerts = alerts || [];
        const hosts = uniq(alerts.map((a) => a.host));
        const users = uniq(alerts.map((a) => a.user));
        const rules = uniq(alerts.map((a) => a.rule_name));
        const times = alerts.map((a) => Date.parse(a.timestamp)).filter((t) => !isNaN(t));

        const lines = [];
        const sevMix = SEV_ORDER.map((s) => [s, alerts.filter((a) => a.severity === s).length])
            .filter(([, n]) => n).map(([s, n]) => `${s} ${n}`);
        lines.push(`Alerts: ${alerts.length}` + (sevMix.length ? ` (${sevMix.join(', ')})` : ''));
        if (times.length) {
            const first = Math.min(...times), last = Math.max(...times);
            lines.push(`First alert: ${utc(first)}`);
            lines.push(`Last alert: ${utc(last)}` + (last > first ? ` (span ${span(last - first)})` : ''));
        }
        if (hosts.length) lines.push(`Affected hosts (${hosts.length}): ${capped(hosts)}`);
        if (users.length) lines.push(`Affected users (${users.length}): ${capped(users)}`);
        const ruleCounts = counted(alerts.map((a) => a.rule_name));
        if (ruleCounts.length) lines.push(`Rules (${rules.length}): ${capped(ruleCounts)}`);
        const mitre = uniq(alerts.map((a) => [a.mitre_tactic_name, a.mitre_technique_id && `${a.mitre_technique_id}${a.mitre_technique_name ? ' ' + a.mitre_technique_name : ''}`]
            .filter(Boolean).join(' / ')));
        if (mitre.length) lines.push(`MITRE: ${capped(mitre)}`);

        const key = [
            ['Source IPs', 'source_ip'], ['Destination IPs', 'destination_ip'],
            ['Processes', 'process_name'], ['Parent processes', 'parent_process_name'],
            ['Files', 'file_name'], ['File hashes', 'file_hash'],
        ].map(([label, f]) => [label, uniq(alerts.map((a) => a[f]))])
            .filter(([, vs]) => vs.length).map(([label, vs]) => `  ${label}: ${capped(vs)}`);
        if (key.length) lines.push('Key fields:', ...key);
        const hl = highlighted(alerts);
        if (hl.length) lines.push('Highlighted fields:', ...hl);

        const evidence = [`${plural(alerts.length, 'alert')} grouped for investigation.`];
        if (hosts.length) evidence.push(`Affected hosts: ${capped(hosts)}.`);
        if (users.length) evidence.push(`Affected users: ${capped(users)}.`);
        if (rules.length) evidence.push(`Triggered rules: ${capped(rules)}.`);

        return {
            title: title(alerts),
            description: lines.join('\n'),
            evidence: evidence.join(' '),
            severity: highestSeverity(alerts),
        };
    }

    const api = { build, title };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.IonCaseDraft = api;
})(this);
