/* Progressive enhancement: content and final diagram states are readable without JS. */
(() => {
  const toggle = document.querySelector('.nav-toggle');
  const links = document.querySelector('.nav-links');
  if (toggle && links) {
    const close = () => {
      links.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = '≡';
    };
    toggle.addEventListener('click', () => {
      const open = !links.classList.contains('open');
      links.classList.toggle('open', open);
      toggle.setAttribute('aria-expanded', String(open));
      toggle.textContent = open ? '×' : '≡';
    });
    links.addEventListener('click', e => { if (e.target.closest('a')) close(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && links.classList.contains('open')) { close(); toggle.focus(); }
    });
    window.matchMedia('(min-width:761px)').addEventListener('change', close);
  }

  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  const active = new Set();
  const animate = (el, frames, options = {}) => {
    if (reduce.matches || !el || !el.animate) return;
    const animation = el.animate(frames, {
      duration: 480, easing: 'cubic-bezier(.2,.65,.3,1)', ...options
    });
    active.add(animation);
    animation.onfinish = animation.oncancel = () => active.delete(animation);
  };
  const playMap = map => {
    map.querySelectorAll('.map-row:not(.static-row)').forEach((row, i) => {
      animate(row.querySelector('.flow-arrow'), [
        { transform: 'translateX(-8px)', opacity: .3 }, { transform: 'translateX(0)', opacity: 1 }
      ], { delay: i * 180, duration: 450 });
      animate(row.querySelector('.after'), [
        { transform: 'translateX(9px)', opacity: .35 }, { transform: 'translateX(0)', opacity: 1 }
      ], { delay: 180 + i * 180 });
    });
    animate(map.querySelector('.path-bar span'), [
      { transform: 'scaleX(0)' }, { transform: 'scaleX(1)' }
    ], { duration: 1400 });
  };
  const replayButtons = document.querySelectorAll('.map-replay');
  const updateMotion = () => {
    if (reduce.matches) active.forEach(animation => animation.cancel());
    replayButtons.forEach(button => { button.hidden = reduce.matches || !Element.prototype.animate; });
  };
  replayButtons.forEach(button => {
    button.addEventListener('click', () => {
      if (button.disabled || reduce.matches) return;
      playMap(button.closest('.change-map'));
      button.disabled = true;
      setTimeout(() => { button.disabled = false; }, 1450);
    });
  });
  updateMotion();
  reduce.addEventListener('change', updateMotion);
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const element = entry.target;
      observer.unobserve(element);
      if (element.classList.contains('change-map')) playMap(element);
      else if (element.classList.contains('workflow')) {
        element.querySelectorAll('li').forEach((li, i) => animate(li, [
          { transform: 'translateY(10px)', opacity: .4 }, { transform: 'translateY(0)', opacity: 1 }
        ], { delay: i * 130 }));
      } else animate(element, [
        { transform: 'translateY(14px)', opacity: .5 }, { transform: 'translateY(0)', opacity: 1 }
      ]);
    }), { threshold: .18 });
    document.querySelectorAll('.motion,.change-map,.workflow').forEach(element => observer.observe(element));
  }
})();
