#!/usr/bin/env bash
# Prepare the pinned inputs UniXNU's GPU user-space scripts expect under .cache/ (run from the UniXNU checkout root):
#   .cache/mesa-work               Mesa at adreno-compiler-inputs.json's commit, sparse, with the recorded patches applied in order
#   .cache/mesa-tools/bin/bison    bison 3.8.2 from the pinned, hash-checked tarball (macOS ships 2.3)
#   .cache/mesa-venv               meson/Mako/... from scripts/requirements-adreno-compiler.txt
#   .cache/gpu-reference/metal2vulkan  metal2vulkan at gpu-metal-vulkan-inputs.json's translator pin, unpatched (the bridge
#                                  build applies its recorded patches itself)
# NEED_MESA / NEED_BISON / NEED_VENV = false skip a part restored from the cache. Every pin is checked; nothing is executed from
# the fetched sources here except bison's own build.
set -euo pipefail
ROOT=$(pwd)
PINS=scripts/data/adreno-compiler-inputs.json
[ -f "$PINS" ] || { echo "::error::run from the UniXNU checkout root"; exit 1; }
mkdir -p .cache

fetch_commit() {   # dir commit url...: sparse-capable single-commit fetch, first URL that serves the commit wins
  local dir=$1 commit=$2; shift 2
  local url
  for url in "$@"; do
    # A named remote: a partial (blob:none) clone needs a promisor remote to fetch the checked-out blobs later.
    git -C "$dir" remote remove origin 2>/dev/null || true
    git -C "$dir" remote add origin "$url"
    if git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$commit"; then
      git -C "$dir" checkout -q FETCH_HEAD
      return 0
    fi
    echo "fetch from $url failed, trying the next source"
  done
  echo "::error::no source served $commit"; return 1
}

if [ "${NEED_MESA:-true}" = true ]; then
  commit=$(jq -r .mesa.commit "$PINS"); tree=$(jq -r .mesa.tree "$PINS")
  rm -rf .cache/mesa-work
  git init -q .cache/mesa-work
  git -C .cache/mesa-work sparse-checkout set $(jq -r '.mesa.sparse_directories[]' "$PINS")
  fetch_commit .cache/mesa-work "$commit" "$(jq -r .mesa.repository "$PINS")" "$(jq -r .mesa.mirror "$PINS")"
  [ "$(git -C .cache/mesa-work rev-parse HEAD)" = "$commit" ] || { echo "::error::Mesa commit differs"; exit 1; }
  [ "$(git -C .cache/mesa-work rev-parse 'HEAD^{tree}')" = "$tree" ] || { echo "::error::Mesa tree differs"; exit 1; }
  for patch in $(jq -r '.patches[]' "$PINS"); do
    git -C .cache/mesa-work apply "$ROOT/$patch" || { echo "::error::Mesa patch $patch does not apply"; exit 1; }
    echo "applied $patch"
  done
fi

if [ "${NEED_BISON:-true}" = true ]; then
  url=$(jq -r .bison.url "$PINS"); sum=$(jq -r .bison.sha256 "$PINS"); bytes=$(jq -r .bison.bytes "$PINS")
  work=$(mktemp -d)
  curl -fsSL --retry 3 "$url" -o "$work/bison.tar.xz"
  [ "$(stat -f %z "$work/bison.tar.xz")" = "$bytes" ] || { echo "::error::bison size differs"; exit 1; }
  echo "$sum  $work/bison.tar.xz" | shasum -a 256 -c -
  tar -xf "$work/bison.tar.xz" -C "$work"
  (cd "$work"/bison-* && ./configure -q --prefix="$ROOT/.cache/mesa-tools" && make -s -j"$(sysctl -n hw.ncpu)" && make -s install)
  rm -rf "$work"
fi
"$ROOT/.cache/mesa-tools/bin/bison" --version | head -n 1

if [ "${NEED_VENV:-true}" = true ]; then
  rm -rf .cache/mesa-venv
  python3 -m venv .cache/mesa-venv
  .cache/mesa-venv/bin/pip install -q --disable-pip-version-check -r scripts/requirements-adreno-compiler.txt
fi
.cache/mesa-venv/bin/meson --version

# metal2vulkan is fetched fresh every run (small with the blob filter); its build state lives in build/m2v-target.
M2V=scripts/data/gpu-metal-vulkan-inputs.json
m2v_commit=$(jq -r .translator.commit "$M2V")
rm -rf .cache/gpu-reference/metal2vulkan
mkdir -p .cache/gpu-reference
git init -q .cache/gpu-reference/metal2vulkan
fetch_commit .cache/gpu-reference/metal2vulkan "$m2v_commit" "$(jq -r .translator.repository "$M2V")"
# The recorded file hashes of the pin (the same check the qualification scripts make).
jq -r '.translator.files | to_entries[] | "\(.value)  .cache/gpu-reference/metal2vulkan/\(.key)"' "$M2V" | shasum -a 256 -c -
echo "PASS: pinned GPU inputs ready (Mesa $(git -C .cache/mesa-work rev-parse --short HEAD), metal2vulkan ${m2v_commit:0:12})"
