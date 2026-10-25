# Wix editor checklist

Site built 26 October 2026 from `docs/site-copy-v2.md`. Work through this in order, in the editor. Nothing here needs code.

- Preview: https://michael6811.wixsite.com/mycio-1
- Editor: https://michael6811-my-site.editor.wix.com/edit/od/c6aa8024-d3db-46f9-b3f2-e7dde504283a?metaSiteId=14659ddf-8cee-4b7b-89e9-8716915db2a7
- The first attempt (mycio, from the long brief) is a separate site. Delete it from the Wix dashboard so there is one.

## 1. Pages: confirm all four exist

Wix's build log listed Home, Who we are and Privacy only. Open the Pages panel and check for **What we do** and **Contact**. If either is missing, say so and I send an update to the build with just those pages. Do not hand-build them from scratch; the copy is in `docs/site-copy-v2.md` and the builder can place it faster.

## 2. Settings, before anything visual

- Site language: English (NZ). Region: New Zealand. Currency: NZD. Time zone: Pacific/Auckland. Wix defaults to US and Los Angeles.
- Apps: keep Wix Forms. Remove anything else the builder installed (the first build added Bookings, Hotels, Invoices and Members Area).
- Unpublish until review is done, or accept that the wixsite.com address is public now and carries Wix branding.

## 3. Delete what the brief did not ask for

Walk every page top to bottom. Remove any of these on sight: testimonial blocks, stat counters other than the $500k, FAQ, blog feed, social icons, "Our services" grids with icons, stock photos, chat widget, Wix "made with" badge, newsletter sign-up, map.

## 4. Images: swap each placeholder for the uploaded file

All ten are in Media Manager under Site Files. Match by file name.

| Slot | File | Notes |
|---|---|---|
| Home hero, full width behind copy | founders-1672.webp | Copy on the left. Fade the right edge to paper if the editor allows a gradient overlay; otherwise leave it clean. Keep faces out from under text. |
| Home, One team, column 01 | pillar-cio-1536.webp | Crop 4:3 or 3:2, all four the same. |
| Home, One team, column 02 | pillar-transformation-1536.webp | |
| Home, One team, column 03 | pillar-ai-1536.webp | |
| Home, One team, column 04 | pillar-security-1536.webp | |
| Home, Who turns up | client-conversation-1536.webp | Oblique, no faces to camera. |
| Who we are, Elton | elton-900.webp | Portrait 4:5, object position top. |
| Who we are, Michael | michael-900.webp | Same crop as Elton. |
| Who we are, header or How we are built | brand-wall-1672.webp | Optional. |
| Header logo, only if the CSS wordmark is not reproducible | myCIO-logo.png | Prefer typing `my` + orange slash + `CIO` as text so it scales. |

## 5. Type and colour

- Font: Hanken Grotesk everywhere. Headlines weight 300 (Light). If the editor offers only Regular, use Regular and reduce size by 10 percent.
- Second line of every headline: orange #cf581e. First line charcoal #202a30.
- Section labels: small caps, letter-spaced, charcoal, 12 to 13px.
- Body: 17 to 18px, line height 1.55, charcoal.
- Background #f5f3ee on every section. No white sections, no dark bands except the optional orange form band.
- Buttons: orange fill, charcoal or paper text, 6px radius. One button text: Book a 30-minute call.
- Columns get a 2px orange rule on top. Nothing gets a shadow, a border radius above 6px, or a background colour that makes it a card.

## 6. Copy check

Open `docs/site-copy-v2.md` beside the editor and read each section aloud against the page. The builder paraphrases. Any sentence that is not in the doc is replaced with the one that is. Search the whole site for: "em dash", "two people", "both of them", "world-class", "seamless", "cutting-edge", "solutions". Delete every instance.

## 7. Form

- Both forms: exactly three fields. Your name · Your email · What would make the biggest difference this year?
- Submit button text: Book a 30-minute call.
- Submissions: email notification to hello@mycio.co.nz. Confirm in Wix Forms settings.
- Success message: We will come back to you within one business day.

## 8. Before the domain moves

- Technology transformation outcome filled in. "[to come]" cannot go live.
- Sector and contract type added to the $500k outcome line.
- Privacy page reviewed.
- Mobile preview of all four pages: no horizontal scroll, hero text readable over the photo.
- Then: Premium plan, connect mycio.co.nz, update DNS, retire GitHub Pages.
