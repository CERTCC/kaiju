---
name: ghidra-update
description: Update kaiju for a new Ghidra version
---

# Ghidra Version Update

Update kaiju to support a new Ghidra version. The argument is the version number (e.g., "12.1", "11.4.2").

## Steps

1. **Check if the Ghidra version is released**: Search for it on https://github.com/NationalSecurityAgency/ghidra/releases to confirm the version exists and get the release date.

2. **Review API changes**: Fetch the API changes page at `https://ghidradocs.com/{version}_PUBLIC/api-changes.html` (from the previous patch version, e.g., for 12.1 fetch `12.0.4_PUBLIC→12.1_PUBLIC`). Also check `https://www.ghidradocs.com/{version}_PUBLIC/docs/ChangeHistory.html` for notable changes. Focus on removed/renamed classes and changed method signatures.

3. **Search kaiju source for affected APIs**: Grep the `src/` directory for any class/method names that were removed or renamed in the new version. Use the Explore agent for broad searches.

4. **Update CI workflow matrices** — append the new version string to the `ghidra_version` array in both:
   - `.github/workflows/release_on_tag.yml` (line ~21)
   - `.github/workflows/run_tests_on_push_pr.yml` (line ~21)

5. **Update CHANGELOG.md** — add a `## YYMMDD` entry at the top (under `# Current Release`) with:
   ```
   ## YYMMDD
   - Improvements:
   * Support for Ghidra {version}
   ```

6. **Update README.md** — add the new version's `X.Y.x` pattern to the supported versions list (line ~47).

7. **Fix any compilation breaks** — if API changes broke the build:
   - Add Manifold preprocessor flags in `build.gradle` (lines ~109-118) if needed for conditional compilation
   - Add `#if VERSION == "true"` guards in Java source if the API change is version-conditional
   - Or fix imports/usages directly if the old API is gone across all supported versions

8. **Verify the build** — build against the new Ghidra version:
   ```
   GHIDRA_INSTALL_DIR=~/Ghidra/ghidra_{version}_PUBLIC ./gradlew -PKAIJU_SKIP_Z3_BUILD --build-cache install
   ```
   Also verify backward compatibility by building against the previous version.

9. **Commit and create PR** — commit all changes on a branch named `ghidra-{version}`, push to the user's fork, and create a PR to CERTCC/kaiju.

## Notes

- Previous updates typically only touched the 3 config files (workflows + changelog + README). Source changes are rare and usually involve Jython/Guava or Ghidra API removals.
- The Manifold preprocessor flags (`GHIDRA_10_4`, `GHIDRA_11_1`) in `build.gradle` are for compile-time conditional code. Add a new flag only if there's an API break that affects some versions but not others.
- `INSTALL.md` and `Dockerfile` are updated separately and may be behind the current version range.
- The `dangerouslyDisableSandbox: true` flag is needed for any bash commands that touch `~/.gradle/` or `~/.gitconfig` (the sandbox blocks writes there).