// Layout of the PDF report.
//
// Everything shown comes from report.json, which the renderer builds and serves from memory.
// Values from it are only ever used as strings — never passed to eval() or read as markup — so
// nothing in a report can act as Typst code. No other file, package or font can be loaded.

#let d = json("report.json")
#let w = d.words

#let ink = rgb("#1b1e23")
#let muted = rgb("#5a626e")
#let faint = rgb("#d5d9df")
#let wash = rgb("#f4f5f7")
#let severity-colour = (high: rgb("#b3261e"), medium: rgb("#b25e09"), low: rgb("#2c6e9c"), info: rgb("#6b7280"))
// A shape per severity and confidence, so the meaning survives a black-and-white print.
#let severity-mark = (high: "▲", medium: "◆", low: "●", info: "○")
#let confidence-mark = (verified: "✓", derived: "→", heuristic: "≈")

#let sans = ("Noto Sans SC",)
#let mono = ("JetBrains Mono", "Noto Sans SC")

// Text from the report arrives as a list of pieces; a line may break between two of them. The
// gap adds a break point without adding a character (a zero-width space would end up in the
// PDF's text), so a hash that fits on one line is still found by searching for it. The gap is
// invisibly small but not zero: Typst drops spacing of exactly zero.
#let gap = h(0.001pt)
#let anywhere(pieces) = if pieces.len() == 0 { "" } else { pieces.join(gap) }
// Only one weight of the text font is embedded; a hairline stroke stands in for bold.
#let strong-text(body, fill: ink) = text(stroke: 0.22pt + fill, fill: fill, body)
#let code(s, size: 0.92em, fill: ink) = text(font: mono, size: size, fill: fill, anywhere(s))

#set document(title: d.document_title, date: none)
#set page(
  paper: "a4",
  margin: (x: 18mm, top: 24mm, bottom: 20mm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 7.5pt, fill: muted)
      grid(
        columns: (1fr, auto),
        column-gutter: 12pt,
        anywhere(d.header_name), w.title,
      )
      v(-6pt)
      line(length: 100%, stroke: 0.4pt + faint)
    }
  },
  footer: context {
    set text(size: 7.5pt, fill: muted)
    grid(
      columns: (1fr, auto),
      anywhere(d.tool), counter(page).display("1 / 1", both: true),
    )
  },
)
#set text(font: sans, size: 9.5pt, fill: ink, lang: d.lang, region: if d.lang == "zh" { "cn" } else { none }, fallback: false)
#set par(leading: 0.72em, spacing: 0.9em, justify: false)
#set heading(numbering: "1")
#show heading: set text(weight: "regular")
#show heading.where(level: 1): it => block(above: 20pt, below: 10pt, sticky: true, {
  set text(size: 14pt, stroke: 0.25pt + ink)
  if it.numbering != none {
    text(fill: muted, stroke: none, counter(heading).display(it.numbering))
    h(8pt)
  }
  it.body
  v(-5pt)
  line(length: 100%, stroke: 0.6pt + faint)
})
#show heading.where(level: 2): it => block(above: 14pt, below: 7pt, sticky: true, {
  set text(size: 10.5pt, stroke: 0.2pt + ink)
  it.body
})
#show outline.entry: set text(size: 9.5pt)

// ---- Title ----------------------------------------------------------------------------------

#text(size: 9pt, fill: muted, tracking: 0.6pt, w.title)
#block(above: 8pt, below: 14pt, text(size: 21pt, stroke: 0.3pt + ink, anywhere(d.input_name)))
#grid(
  columns: (auto, 1fr),
  column-gutter: 10pt,
  row-gutter: 5pt,
  ..d.header.map(item => (text(fill: muted, size: 8.5pt, item.at(0)), code(item.at(1), size: 8.5pt))).flatten(),
)
#v(4pt)
#line(length: 100%, stroke: 1pt + ink)

// ---- Summary --------------------------------------------------------------------------------

#heading(numbering: none, w.summary)

#grid(
  columns: (1fr,) * 4,
  column-gutter: 8pt,
  ..d.severities.map(s => block(
    width: 100%,
    inset: (x: 9pt, y: 7pt),
    fill: wash,
    stroke: (left: 2.5pt + severity-colour.at(s.key)),
    {
      text(size: 8pt, fill: severity-colour.at(s.key), severity-mark.at(s.key) + " " + s.label)
      linebreak()
      text(size: 16pt, str(s.count))
    },
  )),
)
#v(4pt)
#grid(
  columns: (auto, 1fr),
  column-gutter: 12pt,
  row-gutter: 6pt,
  ..d.summary.map(item => (text(fill: muted, item.at(0)), anywhere(item.at(1)))).flatten(),
)

#heading(level: 2, numbering: none, outlined: false, w.reading_guide)
#w.reading_guide_text

#w.grouping_guide

#text(fill: muted, w.scope)

#heading(numbering: none, outlined: false, w.contents)
#outline(title: none, depth: 1)

// ---- Chapters -------------------------------------------------------------------------------

#let badge(mark, label, colour, filled: false) = box(
  inset: (x: 4pt, y: 0pt),
  outset: (y: 2.5pt),
  radius: 2pt,
  fill: if filled { colour } else { none },
  stroke: 0.5pt + colour,
  text(size: 7.5pt, fill: if filled { white } else { colour }, mark + " " + label),
)

// A finding stays on one page. The renderer cuts its text and evidence so it always fits.
#let finding(f) = block(
  width: 100%,
  breakable: false,
  above: 10pt,
  below: 10pt,
  inset: (left: 9pt, top: 2pt, bottom: 2pt),
  stroke: (left: 2pt + severity-colour.at(f.severity)),
  {
    set par(spacing: 0.6em)
    block(sticky: true, {
      badge(severity-mark.at(f.severity), f.severity_label, severity-colour.at(f.severity), filled: f.severity != "info")
      h(4pt)
      badge(confidence-mark.at(f.confidence), f.confidence_label, muted)
      h(6pt)
      strong-text(anywhere(f.title))
    })
    block(above: 6pt, below: 6pt, anywhere(f.text))
    set text(size: 8pt, fill: muted)
    for line in f.evidence {
      block(above: 4pt, below: 4pt, grid(
        columns: (auto, 1fr),
        column-gutter: 6pt,
        w.evidence, code(line, size: 7.5pt, fill: ink),
      ))
    }
    if f.more_evidence != none {
      block(above: 4pt, below: 4pt, f.more_evidence)
    }
    block(above: 4pt, {
      if f.references.len() > 0 {
        w.references + " " + text(fill: ink, anywhere(f.references))
        h(10pt)
      }
      w.finding_id + " " + code(f.id, size: 7.5pt)
    })
  },
)

// Several findings of one rule: the title once, then a row per distinct sentence with the files
// it holds for. The block may run over a page; each row stays whole.
#let group(g) = block(
  width: 100%,
  breakable: true,
  above: 10pt,
  below: 10pt,
  inset: (left: 9pt, top: 2pt, bottom: 2pt),
  stroke: (left: 2pt + severity-colour.at(g.severity)),
  {
    set par(spacing: 0.6em)
    block(sticky: true, {
      badge(severity-mark.at(g.severity), g.label, severity-colour.at(g.severity), filled: g.severity != "info")
      h(6pt)
      strong-text(anywhere(g.title))
      h(6pt)
      text(size: 8pt, fill: muted, g.count)
    })
    for row in g.rows {
      block(breakable: false, above: 5pt, below: 5pt, width: 100%, {
        if row.subject != none {
          code(row.subject, size: 7.5pt, fill: muted)
          linebreak()
        }
        anywhere(row.text)
        if row.subjects != none {
          linebreak()
          text(size: 8pt, fill: muted, row.note + " ")
          code(row.subjects, size: 7.5pt)
        }
      })
    }
    if g.not_shown != none {
      block(above: 5pt, below: 2pt, text(size: 8pt, fill: muted, g.not_shown))
    }
  },
)

#let chapter-body(chapter, empty) = {
  if chapter.findings.len() == 0 {
    text(fill: muted, empty)
  }
  if chapter.note != none {
    block(width: 100%, inset: 8pt, fill: wash, chapter.note)
  }
  for f in chapter.findings {
    if f.group { group(f) } else { finding(f) }
  }
}

#heading(numbering: none, d.attention.title)
#if d.attention.findings.len() > 0 { text(fill: muted, d.attention.text) }
#chapter-body(d.attention, d.attention.text)

#for chapter in d.chapters {
  heading(chapter.title)
  chapter-body(chapter, w.no_findings_here)
}

// ---- File inventory -------------------------------------------------------------------------

#heading(w.inventory)

#{
  set text(size: 7pt)
  table(
    // The last column is as wide as half a SHA-256, so a digest takes two lines.
    columns: (1fr, auto, 17%, auto, 136pt),
    align: (left, right, left, right, left),
    inset: (x: 4pt, y: 3.5pt),
    stroke: (x, y) => (bottom: 0.4pt + faint, top: if y == 0 { 0.8pt + ink } else { none }),
    table.header(..d.inventory.head.map(cell => table.cell(fill: wash, text(fill: muted, cell)))),
    ..d.inventory.rows.map(row => (
      code(row.at(0), size: 1em),
      anywhere(row.at(1)),
      anywhere(row.at(2)),
      anywhere(row.at(3)),
      code(row.at(4), size: 0.9em, fill: muted),
    )).flatten(),
  )
}
#if d.inventory.note != none {
  block(width: 100%, inset: 8pt, fill: wash, d.inventory.note)
}

// ---- Coverage and limitations ---------------------------------------------------------------

#heading(w.coverage)

#if d.coverage.truncated {
  block(width: 100%, inset: 8pt, fill: wash, stroke: (left: 2.5pt + severity-colour.medium), d.coverage.status)
} else {
  d.coverage.status
}

#if d.coverage.limitations.len() == 0 {
  text(fill: muted, w.no_limitations)
}

#for group in d.coverage.limitations {
  heading(level: 2, numbering: none, outlined: false, anywhere(group.title))
  anywhere(group.text)
  set text(size: 8.5pt)
  list(
    marker: text(fill: muted, "–"),
    spacing: 5pt,
    indent: 2pt,
    ..group.items.map(anywhere),
    ..if group.more != none { (text(fill: muted, group.more),) },
  )
}
