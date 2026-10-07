#!/usr/bin/env bash
# The core does no I/O: no files, network, processes, environment, clock or
# OS randomness. That is what lets it run unchanged in WebAssembly (browsers,
# Workers, Convex queries) and stay deterministic. This check fails CI if
# that ever changes.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0

# 1. No I/O in the core's source. The one exception is src/random.rs, the
#    opt-in `random` feature (off by default), which must stay feature-gated.
forbidden='std::fs|std::net|std::process|std::env|std::io::std(in|out|err)|std::thread|SystemTime|Instant::now|Timestamp::now|getrandom|thread_rng|OsRng|tokio|async fn'
# (Comment lines are ignored: docs may mention where randomness comes from.)
if grep -rnE "$forbidden" crates/trustgraph-core/src --exclude=random.rs | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'; then
  echo "error: trustgraph-core must not do I/O (matched: $forbidden)" >&2
  status=1
fi

if ! grep -q '^#\[cfg(feature = "random")\]$' crates/trustgraph-core/src/lib.rs; then
  echo "error: the random module must stay behind #[cfg(feature = \"random\")]" >&2
  status=1
fi

# 2. No I/O-capable crates among its dependencies (default features).
deps=$(cargo tree --quiet --package trustgraph-core --edges normal --prefix none | awk '{print $1}' | sort -u)
for crate in getrandom rand rand_core tokio async-std mio reqwest hyper ureq libc; do
  if grep -qx "$crate" <<<"$deps"; then
    echo "error: trustgraph-core depends on \`$crate\`" >&2
    status=1
  fi
done

[ "$status" -eq 0 ] && echo "trustgraph-core is pure: no I/O in source or dependencies"
exit "$status"
