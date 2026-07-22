// A probe that blocks the event loop FOREVER (synchronous infinite loop).
// The in-process runner's Promise-race timeout is powerless against this; only the
// worker sandbox's terminate() can stop it. Used by sandbox.test.js to prove that.
export default {
  id: 'static/evil-hang',
  title: 'Evil hanging probe',
  layer: 'static',
  run() {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // spin — never yields to the event loop, so no async timer can ever fire.
    }
  },
};
