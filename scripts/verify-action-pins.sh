#!/usr/bin/env bash
# Verify that every pinned GitHub Action SHA actually resolves to the tag the
# trailing comment claims.
#
# The pins in .github/workflows were written offline and MUST be checked before
# the workflows are first run. An unverified pin fails closed — the action will
# not resolve and the build breaks — so this is a broken build rather than a
# silent supply-chain risk. Fix it first anyway.
set -euo pipefail

command -v gh >/dev/null || { echo "gh CLI not installed; cannot verify pins"; exit 2; }

fail=0
grep -rhoE 'uses: [^@]+@[0-9a-f]{40} # .+' .github/workflows/ | sort -u | while read -r line; do
  action=$(echo "$line" | sed -E 's|uses: ([^@]+)@.*|\1|')
  sha=$(echo "$line"    | sed -E 's|.*@([0-9a-f]{40}).*|\1|')
  tag=$(echo "$line"    | sed -E 's|.*# (.+)|\1|')
  actual=$(gh api "repos/${action}/git/ref/tags/${tag}" --jq '.object.sha' 2>/dev/null || echo "UNRESOLVED")
  # Annotated tags point at a tag object; dereference it.
  if [ "$actual" != "$sha" ] && [ "$actual" != "UNRESOLVED" ]; then
    deref=$(gh api "repos/${action}/git/tags/${actual}" --jq '.object.sha' 2>/dev/null || echo "")
    [ "$deref" = "$sha" ] && actual="$sha"
  fi
  if [ "$actual" = "$sha" ]; then
    printf '  OK        %-45s %s\n' "$action" "$tag"
  else
    printf '  MISMATCH  %-45s %s (pinned %s, upstream %s)\n' "$action" "$tag" "${sha:0:12}" "${actual:0:12}"
    fail=1
  fi
done
exit $fail
