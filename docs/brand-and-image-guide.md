# Brand and image guide

How the site looks, and how to generate images that match it. The prompts at the bottom are written to be pasted into an image model as they stand, with the character block at the top of each one.

## The wordmark

`my` + orange slash + `CIO`. On the site it is built in code (see `.logo` in any page's style block) so it is crisp at every size. The slash is a parallelogram skewed 17 degrees, in the brand orange. Under it, where there is room: **Strategy · Security · Technology**, uppercase, letter-spaced, with orange dots.

Assets:

- `myCIO-logo-128h.png`: dark wordmark on transparent, for email signatures and documents.
- `myCIO-logo.png`: white wordmark on dark, used in structured data.
- `favicon.svg` and `favicon.ico`: the slash alone on dark.
- `og-image.jpg`: the social preview, 1200 by 630.

To regenerate them, the Playwright script that rendered them is in the session scratchpad (`build/assets.js`), not in the repo, because the site has no build step. The simplest way to regenerate is to ask Claude to re-render them from the wordmark CSS.

## Colour

| Token | Value | Use |
| --- | --- | --- |
| accent | `#ec6a1f` | The slash, buttons, italic emphasis, diagram highlights |
| accent dark | `#d45a14` | Hover states, text links on light backgrounds |
| ink | `#161412` | Body text on light |
| paper | `#faf7f1` | Page background |
| paper 2 | `#f3eee4` | Alternating sand sections |
| night | `#0a0b0e` | Heroes, proof band, the form band, footer |
| dark | `#2b2723` | The "we own" card, the tools floor |

The accent moved from the old terracotta (`#e05a30`) to match the sign and the polo. Nothing else changed.

## Type

Fraunces for headings and italic emphasis. Hanken Grotesk for everything else, including the wordmark (weight 800). Both from Google Fonts.

## Copy rules

- Never an em-dash. Comma, full stop, colon or parentheses.
- NZ English: organisation, standardise, licence (noun).
- Lead on the difference, not the service: everything stays in your name, we own the decisions not the tickets.
- No invented categories, no platform names for things that are a way of working, no leading with a product. Tools get named once, as the floor.
- Speak to the person carrying the decision, whoever they are. Never name a headcount or a sector as a qualifier.
- The four practices are responsibilities of one team, in this order: Fractional CIO (direction), Technology transformation (foundations), AI (what gets built on them), Cyber security (the condition). Do not reorder them and do not add a fifth.

## Photography: the look

Every generated image so far shares one recipe. Keep it.

- **Setting:** a bright, modern New Zealand office. Timber desks, dark charcoal feature walls, black pendant lights, indoor plants, large windows with soft daylight. One orange accent somewhere in frame: a cushion, a notebook spine, a chair, a print on the wall. Never a logo on the wall except the dedicated brand-wall shot.
- **Light:** natural, soft, slightly warm. No studio flash, no dramatic rim light, no blue-tinted "tech" lighting.
- **Camera:** 35 mm or 50 mm look, shallow depth of field, eye-level, candid. Subjects mid-conversation, not posed at the camera, except the two portraits.
- **Wardrobe:** both in the black myCIO polo, with the small my/CIO mark (white letters, orange slash) on the left chest. Dark jeans. No lanyards, no other logos. The early set had Michael in a navy shirt; those are being regenerated and should not be used for new pages.
- **Props:** laptops, paper notebooks, pens, mugs, paper on the table, sticky notes. No stock-photo props: no glowing holograms, no padlock icons, no circuit boards, no robots.
- **Mood:** relaxed, senior, listening. These are the people you would want in the room when the board asks the hard question.
- **Avoid:** suits and ties, handshakes, pointing at charts going up, anyone looking at the camera in a group shot, more than four people, generic "diverse team" compositions, text or UI on screens that has to be read.

## Character blocks

Paste these at the top of every prompt so the likeness holds.

**Elton:** A New Zealand man in his mid-forties, broad build, closely cropped very short blond-grey hair, clean-shaven, warm open smile with slightly flushed cheeks, blue eyes. Wears a black short-sleeved polo shirt with a small white my/CIO wordmark and orange slash on the left chest, and dark jeans. Expressive with his hands when talking.

**Michael:** A New Zealand man in his early forties, lean athletic build, short dark brown hair swept back, full short dark beard with some grey, blue-grey eyes, calm half-smile. Wears a black short-sleeved polo shirt with a small white my/CIO wordmark and orange slash on the left chest, and dark jeans. Often holding a pen and notebook.

## Images in use

| File | Where | What it carries |
| --- | --- | --- |
| founders | Home hero | Two people, standing, in the business |
| site-visit | Home practices, photo band, transformation hero | In the business, not on a call |
| boardroom | Home practices, Fractional CIO hero | Strategy and the board |
| team-screen | Home practices, AI hero | Building with the client's team |
| client-review | Home practices, Cyber security hero | Vendor and risk accountability |
| client-conversation | Home form, How we work | The first conversation |
| workshop | How we work hero, AI first build | Mapping the process on the table |
| founders-laptop | Fractional CIO peers, Who we are | Working beside the IT lead |
| founders-couch | Who we are hero, Contact | The tone of the first conversation |
| elton, michael | Home people, Who we are, The case | Portraits |
| brand-wall | Who we are | The wordmark |
| elton-polo, michael-alt | Spare | Alternate portraits from the first set |

In the branded black polo already: team-screen, site-visit, client-conversation, elton, michael. Still in the first-set wardrobe (navy shirt on Michael) and due for regeneration: founders, boardroom, workshop, founders-laptop, client-review, founders-couch.

Two things to do before launch:

1. **Replace the two portraits with real photographs.** The generated scenes are fine as scenes. A generated portrait on a brand whose promise is "honest, in the room" is a risk the first time a prospect notices. The portrait slots are plain `<img>` tags; replacing the file at `images/elton-900.webp`, `images/elton-450.webp`, `images/michael-900.webp` and `images/michael-450.webp` (4:5 crop) is the whole job.
2. **Generate the missing shots below.** The site reuses `site-visit` and `founders-laptop` twice. It would be better with one more scene each for AI and security.

## Prompts for the shots we still need

Each prompt assumes the character blocks above are pasted first. Landscape shots at 3:2 (1536 by 1024), portraits at 4:5.

**1. AI, on the floor.** Elton and Michael standing at a workbench in a clean light-industrial space (a food processing or manufacturing packing line, out of focus behind), with a shift supervisor in a company fleece. Michael holds a tablet showing a simple form with a large green tick; the supervisor is pointing at something on it and smiling. Elton is listening with his arms loosely folded. Natural daylight from a high window, hi-vis vests in orange over their usual clothes. No readable text on the tablet.

**2. The board question.** A small boardroom, eight seats, timber table. Elton seated, mid-sentence, hands open, explaining something calmly to two people seen from behind (one grey-haired, one in a blazer). Michael beside him with a single page of paper turned toward them. A wall-mounted screen behind shows a simple three-circle diagram in orange, charcoal and grey, no text. Soft daylight, charcoal wall, one plant.

**3. Security, the honest conversation.** Michael and a finance-director type (a woman in her fifties, glasses, cream blouse) at a desk reviewing a printed document with a short checklist of tick boxes. Michael's pen rests on one unticked box. Both are calm; this is a working conversation, not a crisis. Elton in the background at a standing desk on a laptop, out of focus. Natural light.

**4. Handover.** Elton and Michael with a young in-house IT lead (late twenties, hoodie, lanyard-free) at a bank of monitors, the IT lead at the keyboard and clearly driving, Elton and Michael standing back watching with approval. The screens show tidy dashboards with no readable text. This carries "it runs without us in the end".

**5. The walk to the car park.** Elton and Michael walking side by side out of a glass office entrance into daylight, mid-conversation, Michael with a notebook under his arm, Elton laughing. Shot from slightly ahead of them, wide, 3:2. Useful for the How we work page and for LinkedIn.

**6. Portrait, Elton, real-world.** Head and shoulders, 4:5, in the office near a window, looking just off camera as if at someone talking, slight smile, black polo with the small my/CIO mark on the chest. Shallow depth of field.

**7. Portrait, Michael, real-world.** Head and shoulders, 4:5, same window, same framing, black polo with the small my/CIO mark, calm half-smile, looking just off camera.

**8. Social preview, people variant.** Landscape 16:9 (1672 by 941). Elton and Michael standing at the left third of a wide, otherwise empty, soft-grey office wall, a large window at the far right. Leaves the right two-thirds clear for text. Both at ease, hands in pockets, looking at camera. This matches the current hero crop and gives a second option.

## Prompt hygiene

- Always state "no text, no logos, no watermarks" unless the brand wall is the subject.
- Always state the lens and the light. Models drift to studio lighting otherwise.
- Ask for 3:2 or 4:5 explicitly. The site crops to those.
- If a face drifts, regenerate rather than edit. Consistency across the set matters more than any single image.
