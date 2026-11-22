#!/usr/bin/env node
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import process from "node:process";
import { isDeepStrictEqual } from "node:util";
import { parseFixtureInstant } from "./lib/fixture-instant.mjs";
import { loadFixtures } from "./lib/fixtures.mjs";
import { canonicalize } from "./lib/jcs.mjs";
import { verify } from "./lib/verify.mjs";

const defaultFixtures = new URL("../go/pedigree/testdata/fixtures.json", import.meta.url);
const readJson = (file) => JSON.parse(readFileSync(file));

function options(args) {
  const flags = new Map();
  for (let i = 0; i < args.length; i += 2) {
    const [flag, value] = args.slice(i, i + 2);
    if (!["--dir", "--fixtures"].includes(flag) || flags.has(flag) || !value || value.startsWith("--")) {
      throw new Error("Usage: pedigree-verify.mjs --dir <vector dir> [--fixtures <path>]");
    }
    flags.set(flag, value);
  }
  if (!flags.has("--dir")) throw new Error("--dir is required");
  return { dir: flags.get("--dir"), fixturesPath: flags.get("--fixtures") ?? defaultFixtures };
}

function loadRun(args) {
  const { dir, fixturesPath } = options(args);
  const manifest = readJson(join(dir, "manifest.json")).cases;
  const expected = readJson(join(dir, "expected.json")).cases;
  if (!Array.isArray(manifest) || !Array.isArray(expected)) throw new Error("Missing cases array");
  const entries = new Map();
  for (const row of manifest) {
    if (typeof row?.id !== "string" || typeof row.file !== "string" ||
        row.file !== basename(row.file) || !row.file.endsWith(".json") ||
        typeof row.digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(row.digest) ||
        row.digest.length !== 71 || entries.has(row.id)) {
      throw new Error("Invalid manifest case entry");
    }
    entries.set(row.id, row);
  }
  for (const row of expected) {
    if (typeof row?.id !== "string" || !Number.isSafeInteger(row.presentation) || row.presentation < 1 ||
        typeof row.outcome !== "string" || !Array.isArray(row.trusted_inputs_used) ||
        !row.trusted_inputs_used.every((label) => typeof label === "string")) {
      throw new Error("Invalid expected case entry");
    }
  }

  const policies = loadFixtures(readFileSync(fixturesPath));
  const ceilings = { [policies.ceiling_ref]: Buffer.from(canonicalize(policies.ceiling)) };
  return { dir, entries, expected, policies, ceilings };
}

function readCase(entry, dir) {
  if (!entry) throw new Error("no manifest digest");
  let bytes;
  try {
    bytes = readFileSync(join(dir, entry.file));
  } catch (error) {
    throw new Error("cannot check digest " + entry.digest + ": " + error.message);
  }
  const digest = "sha256:" + createHash("sha256").update(bytes).digest("hex");
  if (digest !== entry.digest) {
    throw new Error("digest mismatch: expected " + entry.digest + ", got " + digest);
  }

  return JSON.parse(bytes);
}

function runCase(data, id, { policies, ceilings }) {
  if (data?.id !== id || !Array.isArray(data.presentations)) throw new Error("invalid case data");
  const config = {
    trustAnchors: data.trust_anchors,
    verifierIds: data.verifier_ids,
    ceilings,
    maxTokens: 8,
    maxBytes: 262144,
    maxInvocationLifetimeSeconds: 60,
    replay: { available: data.replay_available, seen: new Set() },
  };
  return data.presentations.map((record, index) => {
    try {
      const { chain, invocation, args } = record;
      const wpt = data.wpt.find((assumption) => assumption.presentation_index === index + 1);
      const trusted = { wpt, consent: data.consent, policies };
      return { record, result: verify({ chain, invocation, args }, trusted, config, data.at) };
    } catch (error) {
      console.error(JSON.stringify(id) + ": presentation " + (index + 1) + ": " + error.message);
      return { record };
    }
  });
}

function main(args) {
  let run;
  try {
    run = loadRun(args);
  } catch (error) {
    console.error(error.message);
    return 2;
  }

  let exitCode = 0;
  const cases = new Map();
  for (const row of run.expected) {
    const { id, presentation } = row;
    if (!cases.has(id)) {
      let data;
      try {
        data = readCase(run.entries.get(id), run.dir);
      } catch (error) {
        console.error(JSON.stringify(id) + ": " + error.message);
        cases.set(id, null);
        exitCode ||= 1;
        continue;
      }
      if (!parseFixtureInstant(data?.at)) {
        console.error(JSON.stringify(id) + ": invalid case timestamp");
        cases.set(id, []);
        exitCode = 2;
      } else {
        try {
          cases.set(id, runCase(data, id, run));
        } catch (error) {
          console.error(JSON.stringify(id) + ": " + error.message);
          cases.set(id, []);
        }
      }
    }
    const presentations = cases.get(id);
    if (presentations === null) continue;
    const checked = presentations[presentation - 1];
    if (!checked) {
      console.error(JSON.stringify(id) + ": missing presentation " + presentation);
    }
    const got = checked?.result?.outcome ?? null;
    const labels = checked?.result?.trustedInputsUsed ?? [];
    const pass = got === row.outcome && got === checked?.record?.outcome &&
      isDeepStrictEqual(labels, row.trusted_inputs_used) &&
      isDeepStrictEqual(labels, checked.record.trusted_inputs_used);
    if (!pass) exitCode ||= 1;
    console.log(JSON.stringify({
      id, presentation, expected: row.outcome, got, trusted_inputs_used: labels,
      status: pass ? "PASS" : "FAIL",
    }));
  }
  return exitCode;
}

process.exitCode = main(process.argv.slice(2));
