const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../site-motion.js'), 'utf8');

function fixture(reduced = false) {
  const animations = [], timers = [];
  const element = () => ({
    events: {}, attrs: {}, hidden: false, disabled: false, focused: false,
    addEventListener(type, callback) { this.events[type] = callback; },
    setAttribute(name, value) { this.attrs[name] = value; },
    focus() { this.focused = true; },
    animate(frames, options) {
      const a = { frames, options, cancelled: false, cancel() { this.cancelled = true; this.oncancel?.(); } };
      animations.push(a); return a;
    }
  });
  const classes = new Set();
  const links = element(), toggle = element(), replay = element();
  links.classList = { contains: x => classes.has(x), remove: x => classes.delete(x), toggle: (x, on) => on ? classes.add(x) : classes.delete(x) };
  const rows = Array.from({ length: 3 }, () => {
    const arrow = element(), after = element();
    return { querySelector: selector => selector === '.flow-arrow' ? arrow : after };
  });
  const bar = element();
  const map = {
    classList: { contains: name => name === 'change-map' },
    querySelectorAll: () => rows,
    querySelector: () => bar
  };
  replay.closest = () => map;
  const media = {
    reduce: { matches: reduced, addEventListener(_, callback) { this.changed = callback; } },
    desktop: { matches: false, addEventListener(_, callback) { this.changed = callback; } }
  };
  const doc = {
    events: {},
    querySelector: selector => selector === '.nav-toggle' ? toggle : links,
    querySelectorAll: selector => selector === '.map-replay' ? [replay] : [map],
    addEventListener(type, callback) { this.events[type] = callback; }
  };
  let observer;
  class Observer {
    constructor(callback) { this.callback = callback; this.observed = new Set(); observer = this; }
    observe(el) { this.observed.add(el); }
    unobserve(el) { this.observed.delete(el); }
    enter(el) { if (this.observed.has(el)) this.callback([{ target: el, isIntersecting: true }]); }
  }
  vm.runInNewContext(source, {
    document: doc,
    window: { matchMedia: query => query.includes('prefers-reduced-motion') ? media.reduce : media.desktop, IntersectionObserver: Observer },
    IntersectionObserver: Observer, Element: { prototype: { animate() {} } },
    setTimeout: callback => timers.push(callback)
  });
  return { animations, timers, links, toggle, replay, media, doc, observer, map };
}

test('diagram animates once on entry, remains finite, and supports bounded replay', () => {
  const f = fixture();
  f.observer.enter(f.map);
  assert.equal(f.animations.length, 7);
  f.observer.enter(f.map);
  assert.equal(f.animations.length, 7, 'scrolling back must not restart it');
  assert.ok(f.animations.every(a => a.options.duration <= 1400 && a.options.iterations !== Infinity));
  f.replay.events.click();
  assert.equal(f.replay.disabled, true);
  const count = f.animations.length;
  f.replay.events.click();
  assert.equal(f.animations.length, count, 'repeat clicks must not queue animation');
  f.timers.shift()();
  assert.equal(f.replay.disabled, false);
});

test('reduced motion skips animation and live preference changes cancel active motion', () => {
  const reduced = fixture(true);
  reduced.observer.enter(reduced.map);
  reduced.replay.events.click();
  assert.equal(reduced.animations.length, 0);
  assert.equal(reduced.replay.hidden, true);
  const f = fixture();
  f.observer.enter(f.map);
  f.media.reduce.matches = true;
  f.media.reduce.changed();
  assert.ok(f.animations.every(a => a.cancelled));
  assert.equal(f.replay.hidden, true);
  f.media.reduce.matches = false;
  f.media.reduce.changed();
  assert.equal(f.replay.hidden, false);
});

test('Escape closes the mobile menu and restores focus; desktop transition resets it', () => {
  const f = fixture();
  f.toggle.events.click();
  assert.equal(f.toggle.attrs['aria-expanded'], 'true');
  f.doc.events.keydown({ key: 'Escape' });
  assert.equal(f.toggle.attrs['aria-expanded'], 'false');
  assert.equal(f.toggle.focused, true);
  f.toggle.events.click();
  f.media.desktop.changed();
  assert.equal(f.toggle.attrs['aria-expanded'], 'false');
});
