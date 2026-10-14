import { z } from "zod";

const ivarFieldPlanSchema = z.strictObject({
  name: z.string().min(1),
  offset: z.number().int().nonnegative(),
  data_type: z.string().min(1),
  type_encoding: z.string().nullable(),
});

/** One class ivar layout planned or applied as a Ghidra structure. */
export const objcIvarPlanItemSchema = z.strictObject({
  class_name: z.string().min(1),
  structure_name: z.string().min(1),
  procedure: z.string().nullable(),
  fields: z.array(ivarFieldPlanSchema),
  size_bytes: z.number().int().min(0).nullable(),
  action: z.enum(["apply", "skip", "invalid"]),
  reason: z.string().nullable(),
});

/** Dry-run or applied Objective-C ivar layouts as Ghidra structures. */
export const applyObjcIvarsSchema = z.strictObject({
  applied: z.boolean(),
  plan: z.array(objcIvarPlanItemSchema),
  results: z.record(z.string(), z.boolean()).nullable(),
  examined: z.number().int().min(0),
  apply_count: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type ApplyObjcIvars = z.infer<typeof applyObjcIvarsSchema>;
