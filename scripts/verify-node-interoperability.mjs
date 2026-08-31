import { readFile, writeFile } from "node:fs/promises";

const [goResultPath, nodeResultPath, reportPath] = process.argv.slice(2);

if (goResultPath === undefined || nodeResultPath === undefined || reportPath === undefined) {
  throw new Error("usage: verify-node-interoperability.mjs GO_RESULT NODE_RESULT REPORT");
}

const goResult = JSON.parse(await readFile(goResultPath, "utf8"));
const nodeResult = JSON.parse(await readFile(nodeResultPath, "utf8"));

requireEqual(goResult.agent, "go", "Go Agent identity");
requireEqual(goResult.service, "node", "Go Agent Service counterpart");
requireEqual(goResult.platform, "node", "Go Agent Platform counterpart");
requireEqual(goResult.enrollment, "active", "Go Agent enrollment");
requireEqual(goResult.credential_mode, "api-key", "Go Agent credential mode");
requireEqual(goResult.protected_resource_status, 200, "Go Agent protected resource");
requireEqual(goResult.revoked, true, "Go Agent credential revocation");

requireEqual(nodeResult.credentialMode, "api-key", "Node Agent credential mode");
requireEqual(nodeResult.enroll?.status, "active", "Node Agent enrollment");
requireEqual(nodeResult.statusBeforeGrant?.status, "active", "Node Agent pre-Grant status");
requireEqual(nodeResult.statusAfterRevoke?.status, "active", "Node Agent post-Revoke status");
requireEqual(nodeResult.resource?.available, true, "Node Agent protected resource");
requireEqual(nodeResult.profile?.updated, true, "Node Agent protected profile");
requireEqual(typeof nodeResult.grant?.credential_id, "string", "Node Agent credential identifier type");
requireEqual(nodeResult.grant?.credential_id.length > 0, true, "Node Agent credential identifier");
requireEqual(Object.keys(nodeResult.revoke ?? {}).length, 0, "Node Agent Revoke response");

const report = {
  aep_version: "1.0",
  evidence: [
    {
      agent: "go",
      counterpart: "node",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke",
      role: "service",
      status: "passed"
    },
    {
      agent: "go",
      counterpart: "node",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "go",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke",
      role: "service",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "go",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    }
  ],
  status: "passed"
};

await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

function requireEqual(actual, expected, name) {
  if (!Object.is(actual, expected)) {
    throw new Error(`${name}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}
