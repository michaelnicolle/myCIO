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
| accent | `#cf581e` | The slash, buttons, the orange line of a headline, rules on top of columns, numerals |
| accent dark | `#b54a16` | Button hover |
| ink | `#202a30` | Headlines and body. A warm charcoal, never black |
| ink soft | `#3f474d` | Longer body copy |
| muted | `#6e7479` | Descriptions under headings, footnotes |
| line | `#d8d4cb` | Hairline rules |
| paper | `#f5f3ee` | Page background |
| paper 2 | `#e7e4dc` | Alternating warm bands, the form band, the proof band |
| dark | `#19252a` | Footer, the dark button on the orange band |

The accent is the burnt orange from the warm editorial reference, between the old terracotta and the sign. Paper is warm off-white. There is no black anywhere; the darkest value is the footer charcoal.

## Type

Hanken Grotesk only. Headlines are **light (300)** at large sizes with tight tracking, which is what makes the site read as designed rather than generated. The second line of a headline is orange. Sub-headings are medium (500). Labels are small caps, letter-spaced 0.18em, charcoal, never orange and never in a pill. Fraunces italic survives in two places: the opening quote on a "moment" column and the "We ask" question, because those are a spoken voice.

## The look

Warm editorial. Think a well-set annual report, not a SaaS landing page.

- Off-white paper, warm grey bands for alternation, one burnt orange, charcoal type.
- No cards. Content sits in columns with a 2px orange rule across the top and an orange numeral. Lists are rows separated by hairlines.
- No shadows, no glows, no gradients except the fade on the hero photo, no pills, no hover lifts. Corners are 6px.
- Section headers are a two-column grid: label and headline on the left, the one-paragraph intro on the right, bottom-aligned.
- The home hero is the standing photo full-bleed with a paper-coloured fade from the left; the copy sits on the light wall. A strip of four small-caps labels runs under it.
- The orange band at the foot of a page is a single row: headline and one line on the left, a dark button on the right.
- The contact form is a white card on the warm band, the only card on the site.

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

## The next batch: oblique, into the room

Nine of the fourteen scenes are two men facing the camera. That reads as stock, and it is the strongest generated tell. The next batch shoots the room, not the people: over a client's shoulder, hands on the table, the people small and the window large. The viewer stands in the room and sees the outcome being made. Keep the frontal shots for the two portraits and the hero pair only.

Rules for the batch:

- Camera at the far end of the table or just behind a client's shoulder. Elton and Michael are in profile or three-quarter, never looking at the lens.
- The subject of the frame is the work: a one-page map, a half-drawn Climb on glass, a laptop turned toward the client, an invoice with a pen on it.
- One client in frame where it helps, seen from behind or in profile, so the reader has a seat.
- 35 mm, shallow depth of field on the paper, the people softer. Natural light from the window side.
- Black myCIO polos, dark jeans. No readable text on screens or paper.

**O1. The first call, from the client's chair.** Over the shoulder of a woman in her fifties (cream blouse), looking across a timber table at Elton mid-sentence, hands open, and Michael writing in a notebook. Her shoulder and coffee cup soft in the foreground. 3:2.

**O2. The map on the table.** Top-down, slightly angled, four hands over a single large sheet with a hand-drawn system map, a pen pointing at one box, sticky notes at the edge. Faces out of frame or cropped at the chin. 3:2.

**O3. The Climb on glass.** From behind and to the left, Michael drawing a rising curve with four dots on a glass wall with a marker, Elton and a client watching, all in three-quarter view, window light flaring behind the glass. 3:2.

**O4. The warehouse walk.** From behind, Elton and Michael in hi-vis walking a packing line with a supervisor who is pointing ahead. Shot from twenty metres back, the line and the racking are the subject. 16:9.

**O5. The invoice.** Close on a desk: a printed cloud invoice with a line circled in pen, a laptop edge, Michael's hand on the page, a finance manager's hand holding a mug, both people out of focus above. 3:2.

**O6. The board question.** From the far corner of a boardroom, Elton seated and explaining to four people seen mostly from behind, a simple three-circle diagram on the wall screen behind him, Michael standing by the screen. People small, room large. 16:9.

**O7. The handover.** From behind an in-house IT lead at a bank of monitors, keyboard under her hands, Elton and Michael standing behind her, watching, arms folded, both slightly out of focus. 3:2.

**O8. Leaving.** Through a glass office door from inside, Elton and Michael walking out into daylight with a client, all three in profile, mid-laugh, the door frame as the frame. 16:9.

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
