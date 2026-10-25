# Fix Record for X Chrome Tab Picker

- [x] Identify root cause of missing Chrome tabs in `getDisplayMedia` (Chrome default excludes current tab and requires `selfBrowserSurface: "include"` & `preferCurrentTab: true`) <!-- id: 0 -->
- [x] Patch `startScreenRecording()` in `docs/assets/simple_cat.js` with `preferCurrentTab`, `selfBrowserSurface: "include"`, `surfaceSwitching: "include"`, and resilient fallback <!-- id: 1 -->
- [x] Sync changes to `landing/assets/simple_cat.js` maintaining 100% SHA-256 parity <!-- id: 2 -->
- [x] Add verification test to `tests/test_simplecat_visuals_and_scroll.js` <!-- id: 3 -->
- [x] Run test suites and verify all assertions pass <!-- id: 4 -->
- [x] Git commit and push to `origin/main` <!-- id: 5 -->
