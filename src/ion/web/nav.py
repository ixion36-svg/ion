"""ION's navigation, as one structure.

Generated once from base.html by tools/gen_nav_registry.py, then owned by
hand. The template renders this; nothing hand-lists destinations any more.

Before this existed the same destinations were written out in four places
that had already fallen out of step. The desktop nav listed 55, the mobile
panel 6, the `g` key table 10, and two of those keyboard routes
(/shift-handover and /threat-landscape) appeared in no menu at all, so
they were reachable only by someone who already knew the keystroke.
Deciding which entry was current took 108 separate `.startswith(` calls.

A group is active when one of its items is. That is derived, never stored,
which is what fixes the three cases where a child lit up while its parent
group stayed dark (/response-approvals, /verdict-review, /wallboard).

Alerts also drops a `'/audit' not in path` guard the old markup carried. No
registered route starts with /alerts and contains /audit, so the guard only
ever fired on a 404, and the group it belonged to lit up on those paths
anyway.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Item:
    """One destination.

    `href` is also its default activation prefix, so most entries need
    nothing else. `also` adds further prefixes for a page that owns
    sub-paths under another name. `exact` means activate on an equal path
    only, for a destination that is a prefix of its own siblings.

    `dom_id` and `css` are the hooks app.js toggles to hide an entry the
    user has no permission for, so they are part of the entry, not
    decoration: drop one and that entry becomes visible to everyone.
    `gate` names the licence flag that decides whether the entry renders
    at all. `mobile` is the entry's position in the mobile panel, which is
    its own curated order, and `mobile_label` the shorter label it uses
    there.
    """

    href: str
    label: str
    also: tuple[str, ...] = ()
    also_exact: tuple[str, ...] = ()
    exact: bool = False
    shortcut: str | None = None
    mobile: int = 0
    mobile_label: str | None = None
    dom_id: str | None = None
    css: str | None = None
    new_tab: bool = False
    gate: str | None = None

    is_group = False

    @property
    def panel_label(self) -> str:
        return self.mobile_label or self.label

    def is_active(self, path: str) -> bool:
        if path in self.also_exact:
            return True
        if self.exact:
            return path == self.href
        return path.startswith(self.href) or any(path.startswith(p) for p in self.also)


@dataclass(frozen=True)
class Group:
    """A dropdown. Active when any of its items is."""

    label: str
    items: tuple[Item, ...] = field(default_factory=tuple)
    dom_id: str | None = None

    is_group = True

    def is_active(self, path: str) -> bool:
        return any(i.is_active(path) for i in self.items)


NAV: tuple[Item | Group, ...] = (
    Item(href='/', label='Dashboard', exact=True, shortcut='d', mobile=1),
    Group(
        label='Investigate',
        items=(
            Item(href='/alerts', label='Alerts', shortcut='a', mobile=2),
            Item(href='/cases', label='Cases', shortcut='c', mobile=3),
            Item(href='/verdict-review', label='Verdict Review'),
            Item(href='/observables', label='Observables', shortcut='o', mobile=5),
            Item(href='/entity-timeline', label='Entity Timeline'),
            Item(href='/discover', label='Discover'),
            Item(href='/chat', label='AI Chat', shortcut='i'),
        ),
    ),
    Group(
        label='Respond',
        items=(
            Item(href='/playbooks', label='Playbooks', mobile=6),
            Item(href='/response-approvals', label='Response Approvals'),
            Item(href='/investigation-queue', label='Investigation Queue'),
            Item(href='/investigation-memory', label='Investigation Memory'),
            Item(href='/forensics', label='Forensics', dom_id='nav-forensics-link'),
            Item(href='/pcap', label='PCAP Analyzer'),
            Item(href='/case-grouper', label='Case Grouper', exact=True),
        ),
    ),
    Group(
        label='Threat Intel',
        items=(
            Item(href='/threat-intel', label='Threat Intel', also=('/threat-landscape', '/attack-stories')),
            Item(href='/knowledge-graph', label='Knowledge Graph'),
            Item(href='/canaries', label='Canaries'),
            Item(href='/arkime-traffic', label='Traffic Analytics', exact=True),
        ),
    ),
    Group(
        label='Engineering',
        dom_id='nav-group-engineering',
        items=(
            Item(href='/de', label='DE Workbench', exact=True, gate='de'),
            Item(
                href='/detection-engineering',
                label='Detection Engineering',
                shortcut='e',
                mobile=4,
                mobile_label='Detection',
            ),
            Item(href='/de-proposals', label='Detection Proposals', gate='de'),
            Item(href='/de-quirks', label='System Quirks', gate='de'),
            Item(href='/de-bob', label='Bob Improvement', gate='de'),
            Item(href='/network-map', label='Infrastructure', also=('/network-topology', '/data-flow'), shortcut='n'),
            Item(href='/log-sources', label='Platform Health'),
            Item(
                href='/architecture',
                label='Workflow Orchestrator',
                dom_id='nav-architecture-link',
                css='_ion-s-c8be1ccba6',
            ),
        ),
    ),
    Group(
        label='Reporting',
        items=(
            Item(href='/soc-health', label='SOC Health'),
            # A standalone TV screen with none of base.html's chrome, so it
            # opens in its own tab rather than replacing the analyst's page.
            Item(href='/wallboard', label='Wallboard (TV mode)', new_tab=True),
            Item(href='/executive-report', label='Executive Report'),
            Item(href='/detection-health', label='Detection Health'),
            Item(href='/de-metrics', label='DE Metrics', gate='de'),
            Item(href='/analytics', label='Analytics Engine'),
        ),
    ),
    Group(
        label='GRC',
        dom_id='nav-group-grc',
        items=(
            Item(href='/compliance', label='Compliance', dom_id='nav-grc-compliance'),
            Item(href='/maturity', label='Maturity', dom_id='nav-grc-maturity'),
            Item(href='/security', label='Security Posture', dom_id='nav-security-link'),
            Item(
                href='/change-requests',
                label='Service Desk',
                also=('/bug-reports',),
                dom_id='nav-grc-servicedesk',
            ),
            Item(href='/audit-logs', label='Audit Logs', dom_id='nav-grc-audit'),
        ),
    ),
    Group(
        label='Operations',
        items=(
            Item(href='/analyst', label='SOC Workspace', exact=True, shortcut='s'),
            Item(href='/briefing', label='Shift Operations', also=('/shift-handover',), also_exact=('/daily-standup',)),
            Item(href='/alert-prompts', label='Bob Admin', also_exact=('/bob-eval',)),
            Item(href='/tools', label='Tools'),
            Item(href='/scheduler', label='Job Scheduler', exact=True),
        ),
    ),
    Group(
        label='Knowledge',
        items=(
            Item(href='/guide', label='Training'),
            Item(href='/soc-roles', label='SOC Roles'),
            Item(href='/training', label='Skills & Schedule'),
            Item(href='/workforce', label='Workforce', gate='workforce'),
            Item(href='/daily-work', label='My Day'),
            Item(href='/templates', label='Knowledge Base', also=('/notes', '/documents')),
        ),
    ),
    Group(
        label='Administration',
        dom_id='nav-admin-dropdown',
        items=(
            Item(href='/settings', label='Settings'),
            Item(href='/users', label='Users'),
            Item(href='/integrations', label='Integrations'),
            Item(href='/gitlab', label='GitLab'),
            Item(href='/service-accounts', label='Service Accounts'),
            Item(href='/stories', label='Stories (automation)'),
        ),
    ),)


# Destinations with a keyboard shortcut but no menu entry. Listed so they
# are visible in code review rather than only discoverable by pressing a
# key. Either give them a home in NAV or retire the shortcut.
KEYBOARD_ONLY: dict[str, str] = {
    '/shift-handover': 'h',
    '/threat-landscape': 't',
}


def shortcuts() -> dict[str, str]:
    """The `g` key table, derived. key -> href."""
    table = {key: href for href, key in KEYBOARD_ONLY.items()}
    for entry in NAV:
        items = entry.items if isinstance(entry, Group) else (entry,)
        for i in items:
            if i.shortcut:
                table[i.shortcut] = i.href
    return table


def mobile_items() -> tuple[Item, ...]:
    """The mobile panel, derived. Its own order, not the desktop one."""
    out: list[Item] = []
    for entry in NAV:
        items = entry.items if isinstance(entry, Group) else (entry,)
        out.extend(i for i in items if i.mobile)
    return tuple(sorted(out, key=lambda i: i.mobile))


def destinations() -> tuple[str, ...]:
    """Every href the navigation can reach, menus and shortcuts alike."""
    out: list[str] = []
    for entry in NAV:
        items = entry.items if isinstance(entry, Group) else (entry,)
        out.extend(i.href for i in items)
    out.extend(KEYBOARD_ONLY)
    return tuple(dict.fromkeys(out))
