#!/usr/bin/env bash
# CI for the gateway policy: the test records (projects and the catalog) render (schemas, cross-file rules), the Rego passes opa check, fmt and
# test with them, and both bundles build and load together.
#   needs: python3 with jsonschema and pyyaml, opa, helm
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=1; }

echo "==> records (fixtures/records.yaml: projects and the catalog), rendered"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
data="$tmp/gateway-projects"
if python3 scripts/render-records.py fixtures/records.yaml --out "$data" --catalog-values "$tmp/catalog.yaml"; then
  ok "records render (gen-catalog.py, gen-projects.py)"
else
  bad "records"
fi

echo "==> gateway-models chart, with the rendered catalog"
# What the project registry packages and Argo CD installs (the gateway's own values
# have defaults).
if helm template gateway-models charts/gateway-models -n mini-platform -f "$tmp/catalog.yaml" >/dev/null; then
  ok "chart renders"
else
  bad "chart (helm template charts/gateway-models with the rendered catalog)"
fi

echo "==> opa"
if opa check --strict policies/gateway >/dev/null; then ok "opa check"; else bad "opa check policies/gateway"; fi
if [[ -z "$(opa fmt --list policies/gateway)" ]]; then ok "opa fmt"; else bad "opa fmt (run: opa fmt -w policies/gateway)"; fi
if opa test policies/gateway "$data" >/dev/null; then ok "opa test"; else bad "opa test"; opa test policies/gateway "$data" || true; fi
# The approvals setting's triggers (settings/schema.json) are the ones portal.rego knows.
if python3 - "$(opa eval -d policies/gateway --format raw 'json.marshal(data.portal.known_triggers)')" <<'PY'
import json, sys
schema = set(json.load(open("settings/schema.json"))["approvals"]["required"])
code = set(json.loads(sys.argv[1]))
sys.exit(0 if schema == code else print("schema only:", sorted(schema - code), "code only:", sorted(code - schema)) or 1)
PY
then ok "approval triggers: schema and portal.rego agree"; else bad "approval triggers (settings/schema.json approvals vs portal.rego known_triggers)"; fi
# Build both bundles as the project registry does (tests left out, roots from each
# .manifest) and load them together, as OPA does: overlapping roots fail here.
if opa build -b policies/gateway --ignore '*_test.rego' -o "$tmp/policy.tar.gz" >/dev/null \
   && opa build -b "$data" -o "$tmp/data.tar.gz" >/dev/null \
   && opa eval -b "$tmp/policy.tar.gz" -b "$tmp/data.tar.gz" --fail 'true' >/dev/null; then
  ok "bundles build and load together"
else
  bad "bundles build and load together"
fi

[[ $fail == 0 ]] && echo "All checks passed." || { echo "Some checks FAILED."; exit 1; }
