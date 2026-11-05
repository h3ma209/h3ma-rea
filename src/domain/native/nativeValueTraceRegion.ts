import { z } from "zod";
import { nativeValueTraceSchema } from "./nativeValueTrace.js";

/** Trace inputs scoped to one decompiler region inside a procedure. */
export const nativeValueTraceInRegionInputSchema = z.strictObject({
  procedure: z.string().min(1),
  region_start: z
    .string()
    .min(1)
    .describe("Start address of a structured or unstructured decompiler region."),
  region_stop: z
    .string()
    .min(1)
    .optional()
    .describe("When omitted, the matching region stop from inspect_native_regions is used."),
  direction: z.enum(["forward", "backward"]).default("forward"),
  max_depth: z.number().int().min(0).max(16).default(0),
  max_functions: z.number().int().min(1).max(64).default(1),
  max_call_sites: z.number().int().min(1).max(4096).default(256),
  max_nodes: z.number().int().min(1).max(20_000).default(5_000),
  max_edges: z.number().int().min(1).max(40_000).default(10_000),
  offset: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).max(5_000).default(1_000),
});

/** Value trace bounded to one decompiler region address range. */
export const nativeValueTraceInRegionSchema = nativeValueTraceSchema.extend({
  region: z.strictObject({
    kind: z.enum(["if", "loop", "switch", "unstructured"]),
    start: z.string().min(1),
    stop: z.string().min(1),
  }),
});

export type NativeValueTraceInRegion = z.infer<
  typeof nativeValueTraceInRegionSchema
>;
