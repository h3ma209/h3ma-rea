import { z } from "zod";
import { nativeDispatchMetadataInputSchema } from "../domain/native/objcSwiftMetadata.js";
import { nativeProcedureInputSchema } from "../domain/native/nativeProcedureInput.js";
import { decompileDirectoryInputSchema } from "./decompileDirectory.js";
import { nativeValueTraceInputSchema } from "../domain/native/nativeValueTrace.js";
import { nativeInvestigationTraceLimitsSchema } from "../domain/native/nativeInvestigationGraph.js";
const traceLiteralInputSchema = z.strictObject({
  query: z.string().min(1),
  case_sensitive: z.boolean().default(false),
});

export const DEFAULT_CALL_RELATIONSHIP_DIRECTION = "forward";
const callRelationshipDirectionSchema = z
  .enum(["forward", "backward"])
  .default(DEFAULT_CALL_RELATIONSHIP_DIRECTION);
export type CallRelationshipDirection = z.output<
  typeof callRelationshipDirectionSchema
>;

/** Input schemas shared by MCP registration and enhanced application dispatch. */
export const enhancedInputSchemas = {
  trace_native_values: nativeValueTraceInputSchema,
  inspect_native_dispatch_metadata: nativeDispatchMetadataInputSchema,
  get_objc_classes: z.strictObject({ pattern: z.string().default("") }),
  get_objc_protocols: z.strictObject({}),
  batch_decompile: z.strictObject({
    addresses: z
      .array(z.string().describe("A provider-normalized procedure address"))
      .default([]),
  }),
  decompile_all: decompileDirectoryInputSchema,
  get_call_graph: z.strictObject({
    address: z
      .string()
      .describe(
        "A procedure symbol or address to resolve to its canonical entry",
      ),
    direction: callRelationshipDirectionSchema,
  }),
  analyze_swift_types: z.strictObject({
    category: z
      .enum(["classes", "structs", "enums", "protocols", "extensions", "other"])
      .optional()
      .describe(
        "Limit categorized results to one Swift category; unresolved category observations remain in unclassified.",
      ),
    pattern: z
      .string()
      .optional()
      .describe(
        "Case-sensitive literal filter applied to provider procedure names and their supporting Swift manglings.",
      ),
  }),
  find_xrefs_to_name: z.strictObject({ name: z.string() }),
  binary_overview: z.strictObject({}),
  // Provider input excludes delivery detail, which belongs to the MCP tool contract.
  analyze_function: nativeProcedureInputSchema,
  inspect_native_api: nativeProcedureInputSchema,
  trace_feature: traceLiteralInputSchema,
  trace_call_path: z.strictObject({
    start: z.string().describe("A starting procedure symbol or address"),
    goal: z
      .string()
      .describe("An optional destination procedure symbol or address")
      .optional(),
    direction: callRelationshipDirectionSchema,
  }),
  resolve_external_symbols: z.strictObject({
    binary_path: z
      .string()
      .min(1)
      .describe("Absolute path to binary executable"),
  }),
  scan_embedded_keys: z.strictObject({
    min_entropy: z
      .number()
      .min(2.0)
      .max(8.0)
      .default(4.5)
      .describe("Minimum Shannon entropy threshold (0.0 to 8.0)"),
    max_findings: z
      .number()
      .int()
      .min(1)
      .max(5_000)
      .default(500)
      .describe("Maximum findings to report"),
  }),
  inspect_objc_selector_refs: z.strictObject({
    class_name: z
      .string()
      .min(1)
      .optional()
      .describe("Filter references by exact Objective-C class name"),
    selector: z
      .string()
      .min(1)
      .optional()
      .describe("Filter references by exact selector name"),
    max_selectors: z.number().int().min(1).max(5_000).default(256),
    max_refs: z.number().int().min(1).max(20_000).default(2_000),
    max_records: z.number().int().min(1).max(20_000).default(5_000),
  }),
  inspect_swift_concurrency: z.strictObject({
    max_records: z
      .number()
      .int()
      .min(1)
      .max(20_000)
      .default(5_000)
      .describe("Maximum symbol and procedure records to inspect"),
  }),
  diff_binary_revisions: z.strictObject({
    baseline_document: z
      .string()
      .min(1)
      .describe(
        "Provider document name or path of baseline binary to compare against",
      ),
    max_differences: z
      .number()
      .int()
      .min(1)
      .max(2_000)
      .default(500)
      .describe("Maximum differences to report"),
  }),
  trace_native_ui_action: nativeInvestigationTraceLimitsSchema.extend({
    action: z
      .string()
      .min(1)
      .describe(
        "A unique compiled UI action selector, interface object ID, native symbol or exact function address",
      ),
  }),
} as const;

export type EnhancedToolName = keyof typeof enhancedInputSchemas;
