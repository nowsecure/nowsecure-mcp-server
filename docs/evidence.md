# Evidence integration and testing

This guide covers evidence retrieval for MCP client developers and the live
audit for contributors. For example requests to use with your assistant, see
the [Platform prompts](../README.md#platform-prompts).

## Retrieve evidence for a finding

Select a finding from `get_assessment_findings`, then request evidence for the
same scan:

```json
{
  "app_ref": "<app_ref>",
  "assessment_ref": "<assessment_ref>",
  "check_ids": ["<check_id>"],
  "include_evidence": true
}
```

The response includes the full developer recommendation and an `evidence`
object on each returned finding. `evidence.rows` preserves the observations,
and `evidence.fields` explains their columns. Join row `location_id` references
to `evidence.code_locations[].id` for the code details supplied by the scan,
such as file, class, method, or line information. Referenced ids without code
data appear in `unresolved_location_ids`. Evidence requests require non-empty
`check_ids` and return JSON. The usual severity, affected-only, and finding limit
filters apply.

Evidence defaults to 20 rows per finding, with `total_rows` showing the full
count. While `has_more` is true, pass `next_offset` as `evidence_offset`, keeping
the same `app_ref`, `assessment_ref`, and a single check ID in `check_ids`. Set
`evidence_limit` to choose the page size (maximum 100). Each row is untruncated,
and code locations are fetched only for the returned rows. A row can still be
large; lower `evidence_limit` to reduce context use.

Use `get_finding` for general remediation guidance and the scan evidence to
identify relevant source changes. Empty evidence or unresolved locations are
data gaps. To verify a fix after rescanning, select the new completed scan from
`list_assessments`, pass its explicit `assessment_ref`, and request the same
`check_ids` with `affected_only=false`; an empty findings list does not prove
that the issue passed.

## Measure context consumption with real data

From a source checkout with Go installed, export `NOWSECURE_API_TOKEN` and run
the opt-in live audit:

```sh
NSMCP_EVIDENCE_LIVE_TEST=1 go test ./internal/mcpserver \
  -run '^TestEvidenceLiveContextConsumption$' -count=1 -v
```

It samples up to three apps and three findings per app, comparing triage,
recommendations, and evidence. The report separates exact text and structured
payload bytes, estimates tokens with a bytes/4 heuristic, and counts evidence
rows and code locations. Actual context use depends on the client's chosen
representation and tokenizer. Set `NSMCP_EVIDENCE_AUDIT_PATH` to save the
aggregate JSON report; raw evidence and app identities are excluded.
Set `NSMCP_EVIDENCE_AUDIT_MAX_FINDINGS` (1–100) to widen the sample; values above
three consider all affected scored findings on the sampled apps. The audit also
walks the first paginated finding to verify that every evidence row remains
retrievable.
