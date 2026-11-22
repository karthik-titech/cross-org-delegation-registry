import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.mjs";

/** Error thrown when the fixtures file cannot be used. */
export class FixtureError extends Error {
  constructor(message) {
    super(message);
    this.name = "FixtureError";
  }
}

const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const policySet = (v) => Array.isArray(v) && v.length > 0 &&
  v.every((policy) => typeof policy === "string" && policy.length > 0);

/** Validate fixture decision rows and return an exact lookup using canonical arguments. */
export function indexDecisions(rows) {
  if (!Array.isArray(rows)) throw new FixtureError("Invalid fixture decisions");
  const decisions = new Map();
  const key = (id, action, resource, args) => JSON.stringify([id, action, resource, args]);
  for (const row of rows) {
    if (!object(row) || typeof row.policy_id !== "string" || typeof row.action !== "string" ||
        typeof row.resource !== "string" || !object(row.args) || !["permit", "deny"].includes(row.decision)) {
      throw new FixtureError("Invalid fixture decision row");
    }
    let args;
    try {
      args = canonicalize(row.args);
    } catch (error) {
      throw new FixtureError("Invalid fixture decision arguments: " + error.message);
    }
    const id = key(row.policy_id, row.action, row.resource, args);
    if (decisions.has(id) && decisions.get(id) !== row.decision) {
      throw new FixtureError("Conflicting fixture decisions");
    }
    decisions.set(id, row.decision);
  }
  return (id, action, resource, args) => decisions.get(key(id, action, resource, args));
}

/** Parse fixture policies, checking decision consistency and the canonical ceiling digest. */
export function loadFixtures(bytes) {
  let policies;
  try {
    policies = JSON.parse(bytes);
  } catch (error) {
    throw new FixtureError("Invalid fixture JSON: " + error.message);
  }
  if (!object(policies) || !policySet(policies.ceiling) || !policySet(policies.mandate) ||
      !object(policies.effects)) {
    throw new FixtureError("Invalid fixture policy data");
  }
  const digest = createHash("sha256").update(canonicalize(policies.ceiling)).digest("hex");
  if (policies.ceiling_ref !== "sha256:" + digest) {
    throw new FixtureError("Fixture ceiling digest mismatch");
  }
  indexDecisions(policies.decisions);
  return policies;
}
