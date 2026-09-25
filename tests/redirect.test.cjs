const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(require('node:path').join(__dirname, '../the-case.html'), 'utf8');
const source = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
test('retired case page preserves useful destinations and safely defaults to Home', () => {
  const cases = {'':'index.html', '#proof':'index.html#proof', '#people':'index.html#people', '#book':'contact.html#contact', '#gap':'how-we-work.html#gap', '#ownership':'how-we-work.html#ownership', '#climb':'how-we-work.html#journey-curve', '#flywheel':'how-we-work.html#flywheel', '#https://example.com':'index.html', '#__proto__':'index.html'};
  for (const [hash, expected] of Object.entries(cases)) {
    let destination;
    vm.runInNewContext(source, {location:{hash, replace:value => {destination=value;}}});
    assert.equal(destination, expected);
  }
});
