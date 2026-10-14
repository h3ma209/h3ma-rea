import { describe, expect, it } from "vitest";

import { applyDemangledNames } from "./ApplyDemangledNames.js";
import {
  createAnalysisExecution,
  type AnalysisOperation,
} from "../AnalysisProvider.js";
import { err, ok } from "../../domain/result.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";

const provider = { id: "fixture", name: "Fixture", version: null };

describe("applyDemangledNames", () => {
  it("returns a dry-run plan without renaming", async () => {
    const result = await applyDemangledNames(
      {
        execute: async (operation: AnalysisOperation) => {
          if (operation === "list_names")
            return ok(
              createAnalysisExecution(
                [
                  { address: "0x1000", value: "$s4Test3fooyyF" },
                  { address: "0x2000", value: "_main" },
                ],
                provider,
              ),
            );
          if (operation === "demangle_swift")
            return ok(
              createAnalysisExecution(
                {
                  symbols: [
                    {
                      input: "$s4Test3fooyyF",
                      output: "Test.foo() -> ()",
                      status: "demangled",
                    },
                  ],
                  provenance: [],
                  limitations: [],
                },
                provider,
              ),
            );
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { apply: false, max_names: 500 },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      applied: false,
      rename_count: 1,
      results: null,
      plan: [
        {
          address: "0x1000",
          current_name: "$s4Test3fooyyF",
          demangled: "Test.foo() -> ()",
          action: "rename",
        },
      ],
    });
  });

  it("applies demangled names through set_addresses_names", async () => {
    const result = await applyDemangledNames(
      {
        execute: async (operation: AnalysisOperation) => {
          if (operation === "list_names")
            return ok(
              createAnalysisExecution(
                [{ address: "0x1000", value: "$s4Test3fooyyF" }],
                provider,
              ),
            );
          if (operation === "demangle_swift")
            return ok(
              createAnalysisExecution(
                {
                  symbols: [
                    {
                      input: "$s4Test3fooyyF",
                      output: "Test.foo() -> ()",
                      status: "demangled",
                    },
                  ],
                  provenance: [],
                  limitations: [],
                },
                provider,
              ),
            );
          if (operation === "set_addresses_names")
            return ok(
              createAnalysisExecution({ "0x1000": true }, provider),
            );
          return err(
            new AnalysisCapabilityUnavailableError("fixture", operation, "unused"),
          );
        },
      },
      { apply: true, max_names: 500 },
    );
    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      applied: true,
      results: { "0x1000": true },
    });
  });
});
