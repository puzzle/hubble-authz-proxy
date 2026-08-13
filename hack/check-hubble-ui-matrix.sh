#!/usr/bin/env bash
#
# Checks the E2E matrix against the hubble-ui versions Cilium actually ships.
#
# We parse hubble-ui's internal customprotocol, so what matters is which
# hubble-ui backend a user ends up running — and that is decided by their Cilium
# release, not by us. That mapping is not stable: Cilium 1.19.3 shipped
# hubble-ui v0.13.3 and 1.19.4 shipped v0.13.5, a change inside a patch line
# that no dependency bot reports, because from our side nothing changed at all.
#
# So this reads install/kubernetes/cilium/values.yaml from the newest patch of
# each supported Cilium line and fails if it finds a hubble-ui version the E2E
# matrix does not test. The failure is the notification: it means someone must
# decide whether to widen the matrix or drop the oldest entry.
#
# Runs nightly, not on PRs — it depends on the state of the world, and an
# upstream release must not turn an unrelated PR red.
#
#   ./hack/check-hubble-ui-matrix.sh

set -euo pipefail

# Cilium minor lines we claim to work with. Adding a line here is how "we now
# support 1.21" gets expressed.
LINES=(1.18 1.19 1.20 1.21)

WORKFLOW=".github/workflows/e2e.yml"
REPO="cilium/cilium"

cd "$(dirname "$0")/.."

# --- what we test ----------------------------------------------------------

# Matrix entries are bare tags, one per "- ui:" line. Kept in that shape so
# Renovate's regex manager (which requires a full image reference) cannot
# rewrite them and collapse the matrix onto a single version.
mapfile -t tested < <(grep -oP '^\s*-\s*ui:\s*\K\S+' "$WORKFLOW" | sort -u)

if [[ ${#tested[@]} -eq 0 ]]; then
    echo "::error::found no matrix entries in $WORKFLOW; the parser or the file changed" >&2
    exit 1
fi

echo "E2E matrix tests: ${tested[*]}"
echo

# --- what upstream ships ---------------------------------------------------

api() {
    if [[ -n ${GH_TOKEN:-} ]]; then
        curl -sfL --max-time 30 -H "Authorization: Bearer $GH_TOKEN" "$@"
    else
        curl -sfL --max-time 30 "$@"
    fi
}

# newest_tag prints the highest non-prerelease tag for a minor line, falling back
# to prereleases so an unreleased line (1.21 today) is still checked — that is
# the early warning, and the whole reason to look before it ships.
newest_tag() {
    local line=$1 tags
    tags=$(api "https://api.github.com/repos/$REPO/tags?per_page=100" |
        grep -oP '"name":\s*"\Kv'"${line//./\\.}"'\.[^"]+' || true)
    [[ -z $tags ]] && return 1
    # Prefer a GA tag; sort -V puts v1.20.0-rc.1 before v1.20.0, which is what
    # we want when both exist.
    local ga
    ga=$(grep -v -- '-' <<<"$tags" | sort -V | tail -1)
    if [[ -n $ga ]]; then echo "$ga"; else sort -V <<<"$tags" | tail -1; fi
}

declare -A shipped=()
missing=0
checked=0

for line in "${LINES[@]}"; do
    if ! tag=$(newest_tag "$line"); then
        echo "  $line: no tags published yet, skipping"
        continue
    fi

    ui=$(api "https://raw.githubusercontent.com/$REPO/$tag/install/kubernetes/cilium/values.yaml" |
        grep -A3 'repository: "quay.io/cilium/hubble-ui-backend"' |
        grep -oP 'tag:\s*"\K[^"]+' || true)

    if [[ -z $ui ]]; then
        echo "::warning::$tag: could not read the hubble-ui tag; the chart layout may have changed"
        continue
    fi

    checked=$((checked + 1))
    shipped[$ui]+=" $tag"

    # shellcheck disable=SC2076 # literal match is intended
    if [[ " ${tested[*]} " =~ " $ui " ]]; then
        echo "  Cilium $tag -> hubble-ui $ui  [tested]"
    else
        echo "  Cilium $tag -> hubble-ui $ui  [NOT TESTED]"
        missing=1
    fi
done

echo

if [[ $checked -eq 0 ]]; then
    echo "::error::could not resolve any Cilium line; treating as a failure rather" \
        "than reporting a clean run nobody verified" >&2
    exit 1
fi

if [[ $missing -eq 1 ]]; then
    cat >&2 <<EOF
::error::A supported Cilium release ships a hubble-ui version the E2E matrix does not test.

Add it to the 'include:' list in $WORKFLOW. If it is also the version to build
against, bump defaultBackendImage in e2e_test.go and the go.mod module pin with
it — TestE2EMatrixCoversDefaultPin enforces that those two agree.

Widening the matrix is not automatic: dropping the oldest entry is a decision
about which Cilium releases this proxy still supports.
EOF
    exit 1
fi

# Entries we test that nothing in the window ships any more are not an error —
# people run old Cilium for a long time — but they are worth surfacing, because
# every extra entry costs a CI job on every PR.
for ui in "${tested[@]}"; do
    if [[ -z ${shipped[$ui]:-} ]]; then
        echo "::notice::hubble-ui $ui is tested but no longer shipped by the newest" \
            "patch of any supported Cilium line. Keep it while those releases are" \
            "still in the field; drop it when they are not."
    fi
done

echo "Matrix covers every hubble-ui version the supported Cilium lines ship."
