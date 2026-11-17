# Local build dependency

Based on MIT-licensed [picomatch 4.0.7](https://github.com/micromatch/picomatch/tree/4.0.7). Upstream runtime files and LICENSE are retained. This is a local fork, not an upstream 4.0.8 release.

[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) affects released versions through 4.0.7. The upstream advisory lists no patched version as of 2026-11-18.

The only parser change makes every `+(...)` and `*(...)` repeated extglob a literal before regular expression quantifiers are emitted. This applies even with `maxExtglobRecursion: false`. Ordinary stars, globstars, braces, character classes, optional/alternative extglobs and negation retain upstream behavior. Nekopass build paths do not use repeated extglobs.

Both web and documentation override their transitive picomatch dependency with this local package. `tests/picomatch-security.test.cjs` tests the dependency actually resolved by each project, including bounded subprocess tests of the advisory's patterns. npm's registry audit cannot assess local source, so these explicit tests accompany the existing full registry audit.

Remove the override and local fork after upgrading to a verified upstream fix. This package is used by build tools and is not shipped as a Node.js service.
