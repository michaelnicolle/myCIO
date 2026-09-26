/* Draw each explanation once; the complete SVG remains readable without JS. */
(() => {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');
  const active = new Set();
  reduce.addEventListener('change', () => {
    if (reduce.matches) active.forEach(animation => animation.cancel());
  });
  if (!('IntersectionObserver' in window)) return;
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      observer.unobserve(entry.target);
      if (reduce.matches) return;
      entry.target.querySelectorAll('.draw-path').forEach((path, i) => {
        if (!path.animate || !path.getBoundingClientRect().width) return;
        const animation = path.animate([
          {strokeDasharray: '1', strokeDashoffset: '1'},
          {strokeDasharray: '1', strokeDashoffset: '0'}
        ], {duration: 1200, delay: i * 180, easing: 'ease-out'});
        active.add(animation);
        animation.onfinish = animation.oncancel = () => active.delete(animation);
      });
    });
  }, {threshold: .25});
  document.querySelectorAll('.infographic').forEach(figure => observer.observe(figure));
})();
