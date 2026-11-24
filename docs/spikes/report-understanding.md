# Reading the supplied software

The opening report questions are deterministic projections of existing findings in
Overview/Identity, Structure/Composition, Capabilities and Provenance. Each previews
at most three findings in severity order, retains confidence and an ID, and states
the total count. Empty answers do not claim absence. HTML links to the original finding;
text and PDF carry the ID. The final question routes the reader to coverage and limitations.
No model or new analyzer inference is involved.

The relationship index projects these explicit fact profiles:

- `windows.input-references/references`: declarations and supported supplied-file matches;
- `windows.source-files/records`: caller-root-based driver source candidates;
- `windows.catalog-membership/entries`: supported declared digest comparisons and all
  captured candidate matches, retaining search completeness and hash profile;
- `composition.components`: captured NuGet, VSIX and WinGet dependency relationships.

It retains source paths/field or fact-row locations, literal declarations, original statuses,
unresolved reasons and captured target paths/digests. It does not choose among candidates,
turn a path match into a content check, turn digest agreement into authenticated membership,
or establish runtime resolution, installation eligibility or system trust. Other relationships
remain in their findings and facts; an empty index does not mean there are none.
The reading formats preview 50 rows and state the captured total. Source truncation is
reported separately. Full captured source facts remain accessible in HTML and JSON.

Coverage now consistently treats any recorded content loss or incomplete artifact count as
incomplete, including when the early-truncation flag is false. Complete byte reads do not
claim complete structural or behavioral understanding. Artifact-specific limitations and
run-wide limitations have separate counts; the existing limitation chapter still names
the affected artifacts and reasons.

## Acceptance evidence

On Windows x64, the report tests exercise both languages, inert hostile declarations,
determinism, clipped previews, empty questions and content loss without early truncation.
The relationship table is also rendered through the embedded PDF engine. An engine-to-renderer
test builds multi-file ZIPs with unique, missing and case-ambiguous shortcut targets, alongside
the existing licensed native Shell Link fixture. It verifies that actual parsed reference
facts retain their resolution state and digest through JSON and the reading formats.

Browser checks use two engine-generated pages, including the native shortcut report. They
exercise question-to-finding navigation, relationship-to-source navigation and coverage links
in WebKit and Chromium. The final production page build, 14 page unit tests and 32 browser
tests passed locally. The final report checks passed: 24 rendering regressions, including
PDF, and one end-to-end unique/missing/ambiguous-target test. Workspace Clippy with warnings
denied and formatting passed. Hosted [CI at 2caf6d4](https://github.com/atomsprout/analyze-anything/actions/runs/45360964209)
passed all three core and desktop platform jobs plus the advisory/license gate. Final
combined-head checks remain required after the other milestones are added.

A PDF generated from a ZIP of the existing native Shell Link and INF relationship fixtures
was rendered with Poppler. The opening pages and relationship/coverage page were inspected
for readable text, wrapping and overlap. The final English and Chinese opening pages were
rendered and inspected after adding confidence labels. Export verification passed for the
English HTML, PDF and JSON. The local PDF and page images remain in ignored
`out/milestone-03-*`.
