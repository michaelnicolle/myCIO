# myCIO website

Five self-contained HTML pages. Each page has all its CSS and JavaScript inlined,
so there are no external dependencies. Drop any file anywhere and it renders on its own.

## Pages
- index.html        Home
- what-we-do.html   What we do
- how-we-work.html  How we work
- contact.html      Contact
- 404.html          Not-found page
- .nojekyll         Tells GitHub Pages to serve files as-is

## Deploy (GitHub Pages)
Push these files to the repo. Settings, Pages, set the source to your branch and the
root folder. Live in a minute or two.

## Before launch
- Replace the Calendly placeholder in contact.html (search calendly.com/mycio).
- Decide how the contact form submits. It currently opens a pre-filled email to
  hello@mycio.co.nz. For captured submissions, point it at Formspree or similar.
- Custom domain: add a CNAME file containing mycio.co.nz and set the DNS records
  GitHub asks for.

## Fonts
Fraunces (display serif) and Hanken Grotesk (body) load from Google Fonts at the top
of each file. They need an internet connection to render as intended; without one the
browser falls back to Georgia and a system sans.
