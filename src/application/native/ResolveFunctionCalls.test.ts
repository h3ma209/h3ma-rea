import { describe, expect, it } from "vitest";

import { resolveFunctionCalls } from "./ResolveFunctionCalls.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { functionDossierSchema } from "../../domain/hopperValues.js";
import { ghidraFunctionDossier } from "../../domain/ghidraValues.fixture.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";

const provider = { id: "fixture", name: "Fixture", version: "1" };
const subject = {
  path: "/fixture",
  sha256: "a".repeat(64),
  format: "mach-o" as const,
  architecture: "arm64" as const,
};

const dossier = () =>
  jsonValueSchema.parse({
    ...functionDossierSchema.parse(ghidraFunctionDossier()),
    procedure: {
      address: "0x1000",
      name: "caller",
      classification: null,
      body: {
        available: false,
        reason: "The provider did not report complete function body ranges.",
      },
      signature: null,
      locals: [],
    },
    referenced_names: [
      { address: "0x3000", value: "_objc_msgSend", source_address: "0x1004" },
    ],
    referenced_strings: [
      { address: "0x4000", value: "buildTapped:", source_address: "0x1004" },
    ],
    native_value_flow: {
      available: true,
      provenance: "ghidra-high-pcode",
      operations: [
        {
          id: "call",
          address: "0x1004",
          sequence: 0,
          opcode: "CALLIND",
          is_dead: false,
          block_membership: "member",
          inputs: [],
          output: null,
        },
      ],
      def_use: [],
      effects: [
        {
          operation: "call",
          kind: "indirect_call",
          operand_input: null,
          value_input: null,
        },
      ],
      parameters: [],
      parameter_uses: [],
      truncated: false,
      omitted_operations_lower_bound: 0,
      known_omitted_inputs: 0,
      known_omitted_edges: 0,
      limitations: [],
    },
  });

describe("resolveFunctionCalls", () => {
  it("joins an unresolved objc_msgSend to one decoded implementation", async () => {
    const result = await resolveFunctionCalls(
      {
        execute: async (operation) => {
          if (operation === "analyze_function")
            return ok(
              createAnalysisExecution(dossier(), provider, { subject }),
            );
          if (operation === "resolve_native_call_targets")
            return ok(
              createAnalysisExecution(
                {
                  call_site: "0x1004",
                  procedure: "0x1000",
                  status: "unresolved",
                  mechanism: "computed",
                  targets: [],
                  limitations: [],
                },
                provider,
              ),
            );
          if (operation === "inspect_native_dispatch_metadata")
            return ok(
              createAnalysisExecution(
                {
                  target_sha256: subject.sha256,
                  provider,
                  analysis_profile_digest: null,
                  result: {
                    objc_dispatch_implementations: [
                      {
                        class_name: "BuildViewController",
                        selector: "buildTapped:",
                        method_type: "instance",
                        implementation_address: "0x1800",
                        location: { address: "0x1800", file_offset: null },
                        decode: { status: "decoded", reason: null },
                        evidence: [
                          {
                            kind: "symbol",
                            description: "method",
                            location: { address: "0x1800", file_offset: null },
                          },
                        ],
                      },
                    ],
                    db_save_result: null,
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
      { procedure: "0x1000", max_sites: 256, max_records: 5000 },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      sites: [
        {
          address: "0x1004",
          status: "resolved-indirect",
          basis: "objc-metadata",
          targets: [
            {
              address: "0x1800",
              selector: "buildTapped:",
              class_name: "BuildViewController",
            },
          ],
        },
      ],
    });
  });
});