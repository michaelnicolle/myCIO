const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require('node:path').join(__dirname,'../infographic-motion.js'),'utf8');
function setup(reduced = false) {
  const animations = [], removed = [];
  let intersect, change;
  const preference = {matches:reduced,addEventListener(_, callback){change=callback;}};
  const path = visible => ({getBoundingClientRect:()=>({width:visible?300:0}),animate(frames,options){const a={frames,options,cancelled:false,cancel(){this.cancelled=true;this.oncancel();}};animations.push(a);return a;}});
  const figure = {querySelectorAll:()=>[path(true),path(false)]};
  vm.runInNewContext(source, {matchMedia:()=>preference,window:{IntersectionObserver:true},document:{querySelectorAll:()=>[figure]},IntersectionObserver:class {constructor(callback){intersect=callback;}observe(){}unobserve(target){removed.push(target);}}});
  return {animations,removed,enter:()=>intersect([{isIntersecting:true,target:figure}]),reduce(){preference.matches=true;change();}};
}
test('infographic draws visible paths once without animating hidden mobile variants',()=>{
 const f=setup();f.enter();assert.equal(f.removed.length,1);assert.equal(f.animations.length,1);assert.equal(f.animations[0].options.duration,1200);assert.equal(f.animations[0].options.iterations,undefined);
 f.reduce();assert.equal(f.animations[0].cancelled,true);
});
test('reduced motion leaves complete SVG at rest',()=>{const f=setup(true);f.enter();assert.equal(f.animations.length,0);});
