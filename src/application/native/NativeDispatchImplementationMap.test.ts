import { describe, expect, it } from "vitest";

import { inspectNativeDispatchImplementations } from "./NativeDispatchImplementationMap.js";
import {
  createAnalysisExecution,
  type AnalysisOperation,
} from "../AnalysisProvider.js";
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
  provider: { id: "native-macos", name: "macOS native inspection utilities", version: null },
  analysis_profile_digest: "b".repeat(64),
  result: {
    objc_dispatch_implementations: [
      {
        class_name: "BuildViewController",
        selector: "buildTapped:",
        method_type: "instance",
        implementation_address: "0x1000",
        location: { address: "0x2000", file_offset: 16 },
        decode: { status: "decoded", reason: null },
        evidence,
      },
      {
        class_name: "BuildViewController",
        selector: "missing:",
        method_type: "instance",
        implementation_address: null,
        location: { address: "0x2010", file_offset: 24 },
        decode: {
          status: "partial",
          reason: "implementation_pointer_unmapped_or_encoded",
        },
        evidence,
      },
    ],
    coverage: [
      {
        facet: "objc_dispatch_implementations",
        status: "complete",
        reason: null,
        examined: 2,
        decoded: 2,
      },
    ],
    db_save_result: null,
  },
};

describe("inspectNativeDispatchImplementations", () => {
  it("joins decoded implementations to containing procedures", async () => {
    const result = await inspectNativeDispatchImplementations(
      {
        execute: async (operation: AnalysisOperation, parameters) => {
          if (operation === "inspect_native_dispatch_metadata")
            return ok(createAnalysisExecution(metadata, provider));
          if (operation === "resolve_containing_procedure")
            return ok(
              createAnalysisExecution(
                {
                  query_address: parameters.address,
                  found: true,
                  procedure: {
                    address: "0x1000",
                    name: "-[BuildViewController buildTapped:]",
                  },
                },
                provider,
              ),
            );
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { max_records: 5000, resolve_procedures: true, selector: "buildTapped:" },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      total: 1,
      exhaustive: true,
      items: [
        {
          class_name: "BuildViewController",
          selector: "buildTapped:",
          implementation_address: "0x1000",
          procedure: {
            found: true,
            address: "0x1000",
            name: "-[BuildViewController buildTapped:]",
          },
        },
      ],
    });
  });

  it("keeps unmapped implementations explicit", async () => {
    const result = await inspectNativeDispatchImplementations(
      {
        execute: async (operation: AnalysisOperation) => {
          if (operation === "inspect_native_dispatch_metadata")
            return ok(createAnalysisExecution(metadata, provider));
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { max_records: 5000, resolve_procedures: true, selector: "missing:" },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      items: [
        {
          selector: "missing:",
          implementation_address: null,
          procedure: { found: false, reason: "implementation_unmapped" },
        },
      ],
    });
  });
});
