# myCIO 2027: a clearer way forward

Implemented on `2027-branding`; production remains on `main`.

## Creative direction

Based on the supplied 2027 identity boards: my/CIO, the orange forward slash, the paired slash icon, and Strategy · Security · Technology. The website translates those references into live HTML/CSS and vector artwork, rather than using a flattened screenshot as a logo.

The previous website used warm cream, orange italic serif headings and animated light ribbons. The new direction uses confident sans-serif type, white and stone surfaces, charcoal panels, generous space and purposeful orange. The homepage is rebuilt around “See further. Move forward. With myCIO.”

## Identity system

- CIO Orange: #FF6A00, used for the slash, dark-surface accents and action backgrounds.
- Charcoal: #0B0B0B, used for primary type, navigation and brand panels.
- Stone: #D9D9D9, used for rules and supporting structure.
- White: #FFFFFF, the main reading surface.
- Accessible orange ink: #B94700, used for small text on light backgrounds.
- Hanken Grotesk: one type family, with strong headings and restrained supporting text.

The website wordmark is live type with a CSS slash, an interpretation of the reference, not final outlined master logo artwork. The SVG and ICO favicons use the paired slash. The social-sharing image uses the new wordmark, paired slash and homepage message. The older PNG logo remains a legacy asset.

## Website changes

The homepage has a split editorial hero, a dedicated slash graphic, three brand pillars, the existing $500k+ client result, four linked service rows, founder introductions and a direct closing invitation. The new visual system extends across service, case, process, contact, privacy, error and redirect pages. Their deeper content and the existing form integration remain in place. Inline CSS remains intentional, as documented in CLAUDE.md.

No new client results or credentials have been invented. Copyright remains 2026 because the proposal is being prepared in 2026. The branch is a review proposal and has not been merged or published to the production domain.

## Reviewing locally

From the repository directory run `python -m http.server 8765`, then open http://localhost:8765. Review both desktop and a narrow mobile window. The GitHub branch URL shows source code; it does not host a preview website.


## Validation

All nine HTML pages passed local link/fragment checks and all nine inline executable script blocks passed Node syntax checks. Browser review covered the homepage and services at mobile width, the mobile menu and contact path, and overflow/style checks for the homepage, case, process, contact, privacy and 404 routes. Form submission was not sent to the live inbox. This is a visual refresh, not a complete accessibility audit.
