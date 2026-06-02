# Bob RAG authoring examples

Drop-in scaffolds for the **two content levers** that most improve Bob's
auto-investigation quality. See the file docstrings for exact wiring steps.

| File | Lever | When to use |
|---|---|---|
| `example_kb_article.py` | **KB RAG** (broad, semantic) | Background knowledge for a technique/topic. Surfaces by cosine similarity (top-3, ≥0.65) for any related alert. Scales — author one per technique you care about. |
| `example_alert_prompt_template.py` | **Per-rule guide** (surgical) | A *specific* detection rule whose auto-closure quality is poor. Injected above KB; gives Bob a scoped checklist + expected outputs. |

## Authoring principles (from ION's prompt assembly)

1. **One technique per KB article.** Keeps the embedding tight (better retrieval)
   and the article inside the 3800-token prompt budget (priority order:
   KB → exemplars → skills; long articles get dropped first).
2. **Title is high-signal** — it leads the embedded text. Make it specific and
   alert-like.
3. **Always MITRE-tag** (`T####` / `T####.###`). Tags are the matching key for
   `AlertPromptTemplate` *and* enrich the vector (v0.37/v0.38).
4. **Write a "Triage Decision Guidance" section** — explicit TP signals, benign
   explanations, escalation criteria. This is what an *auto*-investigation needs
   and what most reference KB lacks.
5. **No live external lookups** — ION ships air-gapped; rely only on the alert
   payload + seeded knowledge.

Third lever — **gold exemplars** — needs no authoring: close cases accurately and
record analyst `agreement=True`; Bob retrieves those as few-shot examples.
