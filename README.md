# myCIO website

Static site for myCIO. Hosted on GitHub Pages.

## Files
- `index.html` - home
- `how-we-work.html` - delivery model, engagement routes, what's included
- `contact.html` - call booking, contact form, FAQs
- `404.html` - not-found page
- `styles.css` - all styling
- `site.js` - nav toggle and scroll reveals
- `.nojekyll` - tells GitHub Pages to skip Jekyll and serve files as-is

## Deploy
1. Push these files to the repo.
2. Repo Settings, Pages, set source to the branch and root folder.
3. GitHub serves the site within a minute or two.

## Before launch
- Replace the Calendly placeholder in `contact.html` (search for `calendly.com/mycio`).
- Decide how the contact form submits. It currently opens a pre-filled email to hello@mycio.co.nz. For captured submissions, point it at Formspree or similar.
- If using a custom domain (e.g. mycio.co.nz), add a `CNAME` file containing the domain and set the DNS records GitHub asks for.

## Notes
- All internal links are relative, so the site works on a root domain or a project subpath.
