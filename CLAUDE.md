# myCIO website

Static site (no build step), deployed via GitHub Pages from `main` (custom domain `mycio.co.nz` via `CNAME`). Each `.html` page inlines its own `<style>` block by design — this is intentional for portability, not an oversight, so don't "fix" it by extracting shared CSS.

## Copy style rules

- **Never use em-dashes (—).** Rewrite with a comma, period, colon, or parentheses instead. This applies to all body copy, headings, and meta descriptions across every page.
