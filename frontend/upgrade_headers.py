"""
Third-pass template polish: upgrade the post-fix_headers.py `<section>` to
include an eyebrow label + optional subtitle in the hero area.

For each page in PAGES_META, finds the existing:
    <section class="flex items-end justify-between flex-wrap gap-6 mb-8 rise d-1">
        <h1 class="font-sans...">TITLE</h1>
        [optional <p> subtitle]
        [optional <div class="header-actions">…actions…</div>]
    </section>

And replaces with a richer layout that wraps title/subtitle in a left column
and keeps actions on the right.
"""

from pathlib import Path
import re

TEMPLATES_DIR = Path(r"C:\Users\Tomo\ixion\src\ion\web\templates")

# (filename, eyebrow, icon, color, title_override_or_None, subtitle_or_None)
PAGES_META = [
    # Investigation tools
    ("analyst.html",        "SOC Workspace",          "i-shield",           "cyan",  "Analyst Workspace",        "Investigation tools, knowledge base, and daily workflow."),
    ("briefing.html",       "Start of shift",         "i-calendar",         "cyan",  "Morning Briefing",          "Overnight activity, open cases, and priority alerts for the day."),
    ("shift_handover.html", "Shift change",           "i-clock",            "iris",  "Shift Handover",            "End-of-shift notes and handover log."),
    ("entity_timeline.html","Timeline reconstruction","i-activity",         "cyan",  "Entity Timeline",           "Reconstruct activity for a host, user, or IOC across sources."),
    ("chat.html",           "Operator console",       "i-sparkles",         "iris",  "AI Chat",                   "Conversational assistant grounded in your knowledge base and cases."),
    ("tools.html",          "Analyst toolkit",        "i-zap",              "lime",  "SOC Tools",                 "Decoders, hash calculators, and network utilities."),

    # Threat intel area
    ("threat_hunting.html", "Hypothesis-driven",      "i-target",           "coral", "Threat Hunting",            "Proactive campaign searches across telemetry."),
    ("attack_stories.html", "Narrative intelligence", "i-file-text",        "iris",  "Attack Stories",            "Linked alerts, IOCs and playbooks reconstructed as incidents."),
    ("canaries.html",       "Deception grid",         "i-alert-triangle",   "amber", "Canaries",                  "Tripwire tokens and canary accounts for early breach detection."),
    ("knowledge_graph.html","Entity graph",           "i-network",          "iris",  "Knowledge Graph",           "Interactive visualisation of related observables and entities."),

    # Operations
    ("pcap.html",           "Packet forensics",       "i-network",          "lime",  "PCAP Analyzer",             "Upload captures, extract files, and hunt protocol anomalies."),

    # Engineering
    ("log_sources.html",    "Ingestion health",       "i-activity",         "lime",  "Log Source Health",         "Index lag, source volume and configured pipelines."),
    ("data_flow.html",      "Pipeline visualisation", "i-git-branch",       "cyan",  "Data Flow",                 "End-to-end telemetry pipelines across the stack."),
    ("engineering_analytics.html", "Platform telemetry","i-bar-chart",      "cyan",  "System Analytics",          "Capacity, reliability and throughput across ION and integrations."),
    ("gitlab.html",         "Issue tracking",         "i-git-branch",       "iris",  "GitLab",                    "Open issues, merge requests and assigned work."),
    ("integrations.html",   "External services",      "i-layers",           "cyan",  "Integrations",              "Connected data sources, APIs and service credentials."),

    # Reporting
    ("soc_health.html",     "Operational metrics",    "i-activity",         "lime",  "SOC Health",                "Cluster, ingest and SOC-wide KPIs."),
    ("compliance.html",     "Control coverage",       "i-shield",           "lime",  "Compliance",                "Mapped controls across frameworks and evidence capture."),
    ("executive_report.html","Stakeholder brief",     "i-file-text",        "iris",  "Executive Report",          "Boardroom-ready roll-up of operational posture."),
    ("analyst_efficiency.html","Workload metrics",    "i-users",            "cyan",  "Analyst Efficiency",        "Per-analyst workload, closure rate and MTTR."),
    ("analytics.html",      "Analytics engine",       "i-cpu",              "iris",  "Analytics Engine",          "Query builder, saved searches and scheduled reports."),
    ("maturity.html",       "SOC capability",         "i-layers",           "cyan",  "Maturity Assessment",       "SOC-CMM aligned capability scoring and roadmap."),
    ("security_dashboard.html","Posture overview",    "i-shield",           "lime",  "Security Dashboard",        "Top-level risk and threat posture."),

    # Knowledge
    ("social.html",         "Team space",             "i-users",            "iris",  "Social Hub",                "Announcements, shoutouts and team channels."),
    ("guide.html",          "Operator guide",         "i-book-open",        "iris",  "ION Guide",                 "Getting started, workflows and reference."),
    ("guide_sim.html",      "Training simulator",     "i-target",           "amber", "Training Sim",              "Hands-on alert triage scenarios."),
    ("cyber_range.html",    "Live range",             "i-target",           "coral", "Cyber Range",               "Team-vs-team attack/defend exercises."),
    ("training.html",       "Career development",     "i-book-open",        "iris",  "Training &amp; Skills",     "Career pathways, skills assessment and team competency management."),
    ("notes.html",          "Personal notes",         "i-file-text",        "iris",  "Notes",                     "Your working notepad, queries and links."),
    ("templates.html",      "Report templates",       "i-file-text",        "cyan",  "Templates",                 "Document templates for playbooks and reports."),
    ("documents.html",      "Generated documents",    "i-file-text",        "cyan",  "Documents",                 "Rendered reports and exports."),

    # Admin / system
    ("users.html",          "Identity &amp; access",  "i-users",            "cyan",  "Users",                     "User accounts, roles and sessions."),
    ("audit_logs.html",     "System journal",         "i-file-text",        "amber", "Audit Logs",                "Action-level audit trail across ION."),
    ("profile.html",        "My account",             "i-user",             "cyan",  "Profile",                   "Your profile, preferences and notification settings."),
    ("service_accounts.html","Machine identities",    "i-lock",             "amber", "Service Accounts",          "API keys and non-human identities."),
    ("versions.html",       "Release history",        "i-git-branch",       "iris",  "Versions",                  "Changelog and deployment history."),
    ("settings.html",       "System configuration",   "i-settings",         "cyan",  "System Settings",           "Application configuration and integration wiring."),
]

HEADER_RX = re.compile(
    r'<section class="flex items-end justify-between flex-wrap gap-6 mb-8 rise d-1">\s*'
    r'(<h1[^>]*>.*?</h1>)\s*'
    r'(?:<p[^>]*>[^<]*</p>\s*)?'
    r'(<div[^>]*>.*?</div>\s*)?'
    r'</section>',
    re.DOTALL,
)

COLOR_MAP = {
    "cyan":  "text-ion-cyan",
    "amber": "text-ion-amber",
    "coral": "text-ion-coral",
    "iris":  "text-ion-iris",
    "lime":  "text-ion-lime",
}


def build_header(eyebrow, icon, color, title, subtitle, actions_block):
    col = COLOR_MAP.get(color, "text-ion-cyan")
    has_actions = bool(actions_block and actions_block.strip())
    inner = (
        '<div class="flex-1 min-w-0">\n'
        '  <div class="flex items-center gap-3 mb-4">\n'
        f'    <svg class="w-4 h-4 {col}"><use href="#{icon}"/></svg>\n'
        f'    <span class="label-tiny {col}">{eyebrow}</span>\n'
        '  </div>\n'
        f'  <h1 class="font-sans font-semibold text-[36px] md:text-[44px] xl:text-[52px] leading-[1.05] text-white tracking-[-0.02em]">{title}</h1>\n'
    )
    if subtitle:
        inner += f'  <p class="mt-3 max-w-2xl text-[15px] text-slate-400">{subtitle}</p>\n'
    inner += '</div>\n'

    if has_actions:
        return (
            '<section class="flex flex-wrap items-end justify-between gap-6 mb-8 rise d-1">\n'
            + inner
            + actions_block
            + '</section>'
        )
    return (
        '<section class="mb-8 rise d-1">\n'
        + inner
        + '</section>'
    )


def process(path: Path, meta):
    _, eyebrow, icon, color, title, subtitle = meta
    src = path.read_text(encoding="utf-8")

    match = HEADER_RX.search(src)
    if not match:
        return False

    actions_block = match.group(2) or ""
    # Title always comes from metadata in this phase (we know what each page should be called).
    new_header = build_header(eyebrow, icon, color, title, subtitle, actions_block)
    new_src = src[:match.start()] + new_header + src[match.end():]
    if new_src == src:
        return False
    path.write_text(new_src, encoding="utf-8")
    return True


def main():
    updated = 0
    skipped = 0
    for meta in PAGES_META:
        filename = meta[0]
        path = TEMPLATES_DIR / filename
        if not path.exists():
            print(f"  MISSING: {filename}")
            continue
        if process(path, meta):
            updated += 1
            print(f"  upgraded: {filename}")
        else:
            skipped += 1
            print(f"  no-match: {filename}")
    print(f"\n{updated} upgraded, {skipped} skipped")


if __name__ == "__main__":
    main()
