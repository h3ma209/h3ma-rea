import { describe, expect, it } from "vitest";

import { applyObjcIvars } from "./ApplyObjcIvars.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { err, ok } from "../../domain/result.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";

const provider = { id: "fixture", name: "Fixture", version: null };
const sha = "a".repeat(64);

describe("applyObjcIvars", () => {
  it("plans a class ivar structure without applying it", async () => {
    const metadataPayload = {
      target_sha256: sha,
      provider,
      analysis_profile_digest: null,
      result: {
        objc_dispatch_implementations: [
          {
            class_name: "BuildViewController",
            selector: "viewDidLoad",
            method_type: "instance",
            implementation_address: "0x1000",
            selector_address: null,
            type_encoding: null,
            location: { address: "0x2000", file_offset: 16 },
            decode: { status: "decoded", reason: null },
            evidence: [
              {
                kind: "reference",
                description: "method",
                location: { address: "0x2000", file_offset: 16 },
              },
            ],
          },
        ],
        objc_ivars: [
          {
            class_name: "BuildViewController",
            name: "_title",
            type_encoding: "@",
            offset: 8,
            size: 8,
            alignment: 8,
            location: { address: "0x3000", file_offset: null },
            decode: { status: "decoded", reason: null },
            evidence: [
              {
                kind: "reference",
                description: "ivar",
                location: { address: "0x3000", file_offset: null },
              },
            ],
          },
        ],
        coverage: [],
        db_save_result: null,
      },
    };
    const result = await applyObjcIvars(
      {
        execute: async (operation) => {
          if (operation === "inspect_native_dispatch_metadata")
            return ok(createAnalysisExecution(metadataPayload, provider));
          if (operation === "resolve_containing_procedure")
            return ok(
              createAnalysisExecution(
                {
                  found: true,
                  procedure: { address: "0x1000", name: "viewDidLoad" },
                },
                provider,
              ),
            );
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { apply: false, max_classes: 200, max_records: 5000 },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      applied: false,
      apply_count: 1,
      plan: [
        {
          class_name: "BuildViewController",
          action: "apply",
          fields: [{ name: "_title", offset: 8, data_type: "void *" }],
        },
      ],
    });
  });
});
