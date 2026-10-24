# myCIO website

Static site (no build step), deployed via GitHub Pages from `main` (custom domain `mycio.co.nz` via `CNAME`). Each `.html` page inlines its own `<style>` block by design. This is intentional for portability, not an oversight, so don't "fix" it by extracting shared CSS.

## Structure

The homepage is the story: who it is for, the gap, the four responsibilities, how it runs, what the client owns, who turns up, proof, start with one thing. Every other page is a chapter you can land on from a link without losing the thread.

- `index.html` Why myCIO (the argument)
- `journey.html` the story page: three situations the reader picks from (security vendors, cloud costs, AI stalled), then a clock (the call, day 30, day 90, year one) with each thread carried through every chapter. The form there carries a situation field. Send LinkedIn traffic here.
- `what-we-do.html` the four responsibilities, with anchors `#fractional-cio`, `#ai`, `#security` (and the legacy `#technology-consulting`, `#projects-delivery`)
- `fractional-cio.html`, `technology-transformation.html`, `ai.html`, `cyber-security.html` one page per practice, all on the same four-beat shape: the moment people call, what we take ownership of, the first ninety days, the next practice
- `how-we-work.html` the first conversation, the Climb, the Flywheel, three engagement shapes
- `who-we-are.html` Elton and Michael
- `contact.html` the form (Formspree) and what happens on the call
- `the-case.html` the sales walkthrough that pairs with `docs/quick-win-conversation.md`; footer only, not in the main nav
- `security-operations.html` and `transformation.html` are redirects for old URLs
- `images/` are the generated photographs at two or three widths each; `docs/brand-and-image-guide.md` says which is used where and how to generate more

The four practices are responsibilities of one team, in this order: Fractional CIO (direction), Technology transformation (foundations: identity, cloud, infrastructure), AI (what gets built on the foundations), Cyber security (the condition every piece of work meets). Keep that order and do not add a fifth.

## Brand

The wordmark is `my` + orange slash + `CIO`, built in CSS (`.logo` and `.lg-slash` in every page). Warm editorial system: paper `#f5f3ee`, charcoal `#202a30`, burnt orange `#cf581e`. Hanken Grotesk only, headlines light (300) with the second line in orange, labels small caps in charcoal. No cards, no shadows, no pills: columns with a 2px orange rule on top, lists as hairline rows. The case keeps its older editorial styling on purpose. See `docs/brand-and-image-guide.md`.

## Copy style rules

- **Never use em-dashes (—).** Rewrite with a comma, period, colon, or parentheses instead. This applies to all body copy, headings, and meta descriptions across every page.
- NZ English (organisation, standardise, licence).
- Lead on the nameable difference: everything stays in the client's name, we own the decisions not the tickets. Do not lead with a product or a tool; the five tool names appear once, as the floor.
- Treat in-house IT leaders as peers adding senior capacity, never as people being replaced.
