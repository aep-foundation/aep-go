#!/bin/sh
set -eu

specs_dir=${AEP_SPECS_DIR:-../aep-specs}
output_dir=${AEP_CONFORMANCE_OUTPUT:-.conformance/reports}
implementation_version=${AEP_GO_VERSION:-0.0.0-development}
implementation_version=${implementation_version#v}
adapter=bin/aep-conformance-adapter
manifest=.conformance/capability-manifest.json

mkdir -p "$output_dir" .conformance bin
go build -o "$adapter" ./cmd/aep-conformance-adapter

printf '%s\n' "{\"claims\":[{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"agent\"},{\"profiles\":[\"platform-hosted-identity\"],\"role\":\"platform\"},{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"service\"}],\"implementation\":{\"name\":\"aep-go\",\"version\":\"$implementation_version\"},\"manifest_version\":\"1\"}" > "$manifest"

for role in agent platform service; do
  BUNDLE_GEMFILE="$specs_dir/ietf/Gemfile" bundle exec ruby "$specs_dir/ietf/scripts/run_conformance.rb" \
    --role "$role" \
    --manifest "$manifest" \
    --output "$output_dir/$role.json" \
    -- "$adapter" "$role"
done
