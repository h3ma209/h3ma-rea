import { describe, expect, it } from "vitest";

import { applyObjcSignatures } from "./ApplyObjcSignatures.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { err, ok } from "../../domain/result.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";

const provider = { id: "fixture", name: "Fixture", version: null };
const sha = "a".repeat(64);
const evidence = [
  {
    kind: "binary_metadata" as const,
    description: "Encoded absolute Objective-C method entry",
    location: { address: "0x2000", file_offset: 16 },
    artifact_path: "/tmp/app",
    artifact_sha256: sha,
  },
];

const metadata = {
  target_sha256: sha,
  provider: {
    id: "native-macos",
    name: "macOS native inspection utilities",
    version: null,
  },
  analysis_profile_digest: "b".repeat(64),
  result: {
    objc_dispatch_implementations: [
      {
        class_name: "BuildViewController",
        selector: "buildTapped:",
        method_type: "instance",
        implementation_address: "0x1000",
        type_encoding: "v24@0:8",
        location: { address: "0x2000", file_offset: 16 },
        decode: { status: "decoded", reason: null },
        evidence,
      },
    ],
    coverage: [
      {
        facet: "objc_dispatch_implementations",
        status: "complete",
        reason: null,
        examined: 1,
        decoded: 1,
      },
    ],
    db_save_result: null,
  },
};

describe("applyObjcSignatures", () => {
  it("plans a signature without applying it", async () => {
    const result = await applyObjcSignatures(
      {
        execute: async (operation) => {
          if (operation === "inspect_native_dispatch_metadata")
            return ok(createAnalysisExecution(metadata, provider));
          if (operation === "resolve_containing_procedure")
            return ok(
              createAnalysisExecution(
                {
                  found: true,
                  procedure: { address: "0x1000", name: "buildTapped_" },
                },
                provider,
              ),
            );
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { apply: false, max_methods: 500 },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      applied: false,
      results: null,
      apply_count: 1,
      plan: [
        {
          selector: "buildTapped:",
          signature: "void buildTapped_(void * self, void * cmd)",
          action: "apply",
        },
      ],
    });
  });
});
