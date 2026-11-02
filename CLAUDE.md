# myCIO website

Static site (no build step), deployed via GitHub Pages from `main` (custom domain `mycio.co.nz` via `CNAME`). Each `.html` page inlines its own `<style>` block by design. This is intentional for portability, not an oversight, so don't "fix" it by extracting shared CSS.

## Structure

Four pages plus privacy, on one design system (the one-page home sets it). Every old URL is a redirect stub into these.

- `index.html` the story: hero, proof bento, three places technology decisions get stuck, the gap, one team with four jobs, who turns up, proof, book the call
- `what-we-do.html` the four jobs with anchors `#fractional-cio`, `#transformation`, `#ai`, `#security`; the Climb lives under Fractional CIO; each job carries an outcome row (situation, what we did, what changed) where a real one exists
- `who-we-are.html` Elton, Michael, the team, how we are built
- `contact.html` the form (Formspree) and what happens on the call
- `privacy.html`, `404.html`
- Redirect stubs: `journey.html`, `the-case.html`, `dark-sample.html`, `one-page.html`, `fractional-cio.html`, `technology-transformation.html`, `transformation.html`, `ai.html`, `cyber-security.html`, `security-operations.html`, `how-we-work.html`
- `images/` generated photographs at two or three widths each; `docs/brand-and-image-guide.md` says which is used where and how to generate more
- `docs/site-copy-v2.md` the approved copy and the decisions behind it; `docs/wix-editor-checklist.md` for the Wix build

The four practices are responsibilities of one team, in this order: Fractional CIO (direction), Technology transformation (foundations: identity, cloud, infrastructure), AI (what gets built on the foundations), Cyber security (the condition every piece of work meets). Keep that order and do not add a fifth.

## Brand

The wordmark is `my` + orange slash + `CIO`, built in CSS (`.logo` and `.lg-slash` in every page). Warm editorial system: paper `#f5f3ee`, charcoal `#202a30`, burnt orange `#cf581e`. Hanken Grotesk only, headlines light (300) with the second line in orange, labels small caps in charcoal. No shadows, no pills. Columns with a 2px orange rule on top, lists as hairline rows. The proof bento on the home page is the one place tiles with a hairline border and radius are allowed. Two slow-drifting warm blobs sit behind every page; sections fade up on scroll and that is the whole motion budget. See `docs/brand-and-image-guide.md`.

## Copy style rules

- **Never use em-dashes (—).** Rewrite with a comma, period, colon, or parentheses instead. This applies to all body copy, headings, and meta descriptions across every page.
- NZ English (organisation, standardise, licence).
- Lead on the nameable difference: everything stays in the client's name, we own the decisions not the tickets. Do not lead with a product or a tool; the five tool names appear once, as the floor.
- Voice: plain Kiwi English, outcomes not posture. Say what changes for the business, not what governance it gets. "What changes:" beats "with an owner". Short sentences, fewer words, no consultant vocabulary (posture, evidence, framework, leverage).
- Treat in-house IT leaders as peers adding senior capacity, never as people being replaced.
- myCIO is founder-led by Elton and Michael with a senior team behind them. Never describe it as two people, "the same two people" or "both of them". The founders are in the room; the team has depth.
