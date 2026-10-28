# PHP2Shell discovery and analysis

Use this reference when the user asks which portfolio apps use PHP and could
be impacted by PHP2Shell. The result is a list of observed backend dependencies
to investigate, grounded in `api_hsts` evidence.

## Establish the advisory

As checked on 2026-10-27, PHP's 2026-10-21 announcement describes two
vulnerabilities associated with PHP2Shell:

- CVE-2026-109618: RCE via OOM corruption.
- CVE-2026-109619: RCE via stale global state.

The announcement lists fixes in PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12 and notes
that distribution vendors may supply backports. These are historical reference
values, not a complete or permanently current affected-version rule.

Source: [PHP security announcement, October 21, 2026](https://www.php.net/archive/2026.php#2026-10-21-5).

At execution time, reopen that announcement and its linked advisories. Check
subsequent updates and the vendor advisory if the evidence identifies a vendor
build. If the nickname resolves ambiguously, state the CVEs being evaluated.
Assess each CVE separately when version ranges or prerequisites differ.

## Classify observations

| Available scan evidence | Report as | Follow-up |
| --- | --- | --- |
| Explicit PHP label/header, version in a verified affected range | Potential exposure: advertised affected version | Confirm deployed package, vendor backports, and applicable runtime prerequisites with the service owner |
| Explicit PHP label/header, version missing or unparseable | PHP observed: applicability unknown | Obtain runtime version and patch status |
| Explicit PHP version outside the verified affected range | Advertised version outside affected range | Confirm current deployment and all instances; do not label the app safe |
| Only `.php` path, PHP session-cookie name, or other indirect indicator | PHP suspected: unconfirmed | Confirm the backend runtime before applying a version assessment |
| No PHP indicator in successfully retrieved evidence | PHP not observed in this evidence | State the scan coverage limit; do not infer absence |
| Missing check, empty evidence, failed retrieval, or incomplete paging | Unknown: evidence gap | Retrieve missing evidence or request a new assessment |

Compare parsed version components against the advisory's branch-specific ranges,
not lexicographic strings or a single global minimum. Preserve package suffixes,
prerelease labels, and conflicting versions. Do not infer vendor patch status
from an upstream-looking version banner. If several versions occur for one host,
retain each observation and flag the conflict.

An older scan may predate the advisory or remediation. Describe what was seen at
the scan date and ask the owner to verify the current service. Neither a mobile
app's security score nor the HSTS affected flag determines PHP2Shell exposure.

## Answer the user's portfolio question

Lead with counts of distinct apps with explicit PHP observations and additional
apps with indirect indicators. Within explicit observations, prioritize potential
affected-version matches, then unknown versions. Explain any overlap when one
app contacts several endpoints with different statuses.

For each candidate, return the app identity and group, endpoint/ownership if
known, exact relevant PHP indicator, advertised version, scan date, app_ref,
assessment_ref, and per-CVE classification with rationale. Include an endpoint
summary mapping shared services to all affected app candidates so one backend
remediation can be coordinated across multiple mobile teams.

Report portfolio/evidence coverage separately. If an app has a PHP match but
only part of its evidence was read, keep the match and mark its coverage partial.
If there are zero matches, say "No PHP indicators were observed in the inspected
evidence" and give the inspected count and gaps.

Finish with the current primary advisory links and owner verification actions.
Evidence discovery does not authorize active endpoint testing, configuration
changes, or exploitation.

## Interpretation examples (synthetic, not portfolio results)

- `X-Powered-By: PHP` → PHP observed, version unknown, CVE applicability unknown.
- `Server: nginx` plus `/login.php` → nginx observed, PHP suspected, no PHP
  version established.
- PHP explicitly listed with no host association → retain the app-level PHP
  observation and report endpoint unknown.
- A PHP banner on a third-party analytics host → identify the mobile apps
  contacting that host; route confirmation to the service owner rather than
  claiming that the mobile app itself runs PHP.
