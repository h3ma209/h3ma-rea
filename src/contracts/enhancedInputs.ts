import { z } from "zod";
import { nativeValueTraceInputSchema } from "../domain/native/nativeValueTrace.js";
const traceLiteralInputSchema = z.strictObject({
  query: z.string().min(1),
  case_sensitive: z.boolean().default(false),
});

/** Input schemas shared by MCP registration and enhanced application dispatch. */
export const enhancedInputSchemas = {
  trace_native_values: nativeValueTraceInputSchema,
  inspect_native_dispatch_metadata: z.strictObject({
    max_records: z.number().int().min(1).max(20_000).default(5_000),
  }),
  inspect_native_dispatch_implementations: z.strictObject({
    max_records: z.number().int().min(1).max(20_000).default(5_000),
    class_name: z.string().min(1).optional(),
    selector: z.string().min(1).optional(),
    resolve_procedures: z.boolean().default(true),
  }),
  apply_demangled_names: z.strictObject({
    apply: z.boolean().default(false),
    pattern: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Case-sensitive literal filter applied to current names and demangled text",
      ),
    max_names: z.number().int().min(1).max(10_000).default(500),
  }),
  apply_objc_signatures: z.strictObject({
    apply: z.boolean().default(false),
    class_name: z.string().min(1).optional(),
    selector: z.string().min(1).optional(),
    max_methods: z.number().int().min(1).max(20_000).default(500),
  }),
  resolve_function_calls: z.strictObject({
    procedure: z.string().min(1),
    max_sites: z.number().int().min(1).max(4096).default(256),
    max_records: z.number().int().min(1).max(20_000).default(5_000),
  }),
  get_objc_classes: z.strictObject({ pattern: z.string().default("") }),
  get_objc_protocols: z.strictObject({}),
  batch_decompile: z.strictObject({
    addresses: z
      .array(z.string().describe("A provider-normalized procedure address"))
      .default([]),
  }),
  get_call_graph: z.strictObject({
    address: z
      .string()
      .describe(
        "A procedure symbol or address to resolve to its canonical entry",
      ),
    direction: z.enum(["forward", "backward"]).default("forward"),
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
  analyze_function: z.strictObject({
    procedure: z.string().describe("A procedure name or address"),
  }),
  inspect_native_api: z.strictObject({
    procedure: z.string().describe("A procedure name or address"),
  }),
  trace_feature: traceLiteralInputSchema,
  trace_call_path: z.strictObject({
    start: z.string().describe("A starting procedure symbol or address"),
    goal: z
      .string()
      .describe("An optional destination procedure symbol or address")
      .optional(),
    direction: z.enum(["forward", "backward"]).default("forward"),
  }),
  trace_native_ui_action: z.strictObject({
    action: z
      .string()
      .min(1)
      .describe(
        "A unique compiled UI action selector, interface object ID, native symbol or exact function address",
      ),
    max_depth: z.number().int().min(0).max(32).default(8),
    max_nodes: z.number().int().min(1).max(2_000).default(250),
    max_edges: z.number().int().min(1).max(5_000).default(500),
  }),
} as const;

export type EnhancedToolName = keyof typeof enhancedInputSchemas;
