# myCIO 2027: cut through the noise, move your business forward

Review proposal on `2027-branding`. Production remains on `main`.

## Brand and story

The supplied identity boards establish my/CIO, the orange forward slash, the paired slash icon and Strategy · Security · Technology. The site translates that direction into live type, CSS and vector artwork. The wordmark is an interpretation for review; final outlined logo masters remain a separate production asset.

The central promise is now **Cut through the noise. Move your business forward.** It connects independent technology leadership to three business outcomes: lower costs, simpler work and accountable delivery. The customer brings ambitions, opportunities or challenges and owns the progress; myCIO supplies the clarity, leadership and follow-through.

The existing $500k+ vendor-review result appears immediately after the homepage hero. It describes one client outcome, not a typical result or guarantee. Existing founder experience and independence provide the other proof points. No new client results, endorsements or credentials have been added.

## Page roles and hierarchy

- **Home:** promise, logo and Strategy/Security/Technology identity panel, existing proof, The Climb and The Flywheel, four core services, practical AI, founders, common questions, conversation.
- **What we do:** fractional CIO first, followed by consulting, project delivery and security. Each service explains the opportunity, involvement and outcome.
- **How we work:** Discover, Stabilise, Standardise and Transform, each with a clear output. Security spans every stage. Explains the working relationship, independent advice, ownership without lock-in and continuing improvement.
- **Contact:** one focused form and a clear explanation of the next step. A call is arranged after the enquiry; this is not an instant calendar booking.

AI is visible without becoming the whole brand. It follows the core services and has a dedicated anchor on the services page. An illustrative workflow explains approved knowledge, an AI draft and human review. Value, accuracy, readiness and adoption must be tested before scaling; the diagram makes no quantitative savings claim.

## Visual system and motion

White and stone create breathing room; charcoal gives important moments weight. Orange is used for the slash, actions and direction. One sans-serif family, Hanken Grotesk, strengthens hierarchy and consistency.

- Orange: `#FF6A00`; charcoal: `#0B0B0B`; stone: `#D9D9D9`; white: `#FFFFFF`.
- Darker orange ink is used where small text needs stronger contrast on light surfaces.
- The homepage opens with large Strategy, Security and Technology typography, supported by a smaller myCIO wordmark. The Climb and The Flywheel explain how capability builds and how strategy, transformation and operations reinforce each other. Brief path-drawing animations run once, with reduced-motion support.
- Short, once-only section entrances and workflow sequencing support reading order. There are no perpetual decorative loops or scroll hijacking.
- Reduced-motion preferences are respected initially and when changed. Final content remains readable without JavaScript, including a mobile navigation fallback.
- Styles remain inline per page, as required by `CLAUDE.md`. A small shared script handles navigation and optional motion; there are no new runtime dependencies.

## Design rationale

The implementation applies these principles, rather than claiming a proven conversion uplift:

- [Nielsen Norman Group: homepage usability](https://www.nngroup.com/articles/113-design-guidelines-homepage-usability/): make the purpose and value clear and provide distinct routes into the content.
- [Nielsen Norman Group: purposeful animation](https://www.nngroup.com/articles/animation-purpose-ux/): use movement to explain relationships and changes of state.
- [StoryBrand: the customer as hero](https://storybrand.com/hero/): organise the story around the customer's obstacles and progress, with the brand as guide.
- [GOV.UK: writing for user interfaces](https://www.gov.uk/service-manual/design/writing-for-user-interfaces): clear language, useful headings and understandable next actions.

## Review and validation

Run `python -m http.server 8765 --bind 127.0.0.1` from the repository and open http://127.0.0.1:8765/index.html. The GitHub branch page displays source, not a hosted website preview.

Browser checks covered seven rendered routes at 360, 768 and 1280 pixels, with no horizontal overflow and one main heading per page. Reviewed desktop and mobile layouts, mobile navigation, replay and native contact validation. No test enquiry was sent to the live inbox. Redirect pages retain their destination anchors and now resolve on the current host, so they also work in a branch preview.

Automated checks cover internal links, fragments, local assets, duplicate IDs, structured data, script syntax and the no-em-dash copy rule. Three Node behavioural tests cover finite motion, reduced motion and keyboard/mobile navigation. This is not a complete accessibility audit or a measurement of real conversion performance.

## Landing-page refinement

The homepage uses a brand-led right-hand panel with Strategy, Security and Technology as the focus, supported by a smaller myCIO wordmark. The oversized slash illustration is removed. Decorative section numbers and redundant homepage labels are removed; headings carry the story. Numbering remains only where it explains an ordered process. Visitors do not need a defined problem or AI readiness to start: a desire to improve their business is enough, and myCIO helps discover the opportunities.

## Three-page structure

Home explains what myCIO does and why to work with the founders. What we do provides service depth. How we work explains delivery, independence and accountability. Contact remains a separate enquiry destination with a consistent “Let's talk” invitation. The copy welcomes growth opportunities as well as problems to solve.

The former Why myCIO page is removed from navigation and the sitemap. Its URL redirects to Home, with known fragment links mapped to their equivalent proof, people, process, ownership or contact destinations. With JavaScript disabled it falls back to Home.

## Restored visual storytelling

The Climb and The Flywheel are core explanations, retained from the earlier website and redrawn in the 2027 palette and typography. Home introduces both visually; How we work expands their meaning. The Climb retains Discover, Stabilise, Standardise and Transform, with security throughout. The Flywheel connects strategy and governance, transformation and operations around the customer, secure by design. Mobile receives a legible vertical Climb illustration rather than a scaled-down desktop chart. Both remain visible without JavaScript.

## Homepage visual pacing

The capability climb spans the content width after the proof strip. The continuous-improvement flywheel follows the AI section, before the founders. The standalone Climb and Flywheel title labels are removed on both Home and How we work; story headings introduce their purpose.
