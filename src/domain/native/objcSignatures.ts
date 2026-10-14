import { z } from "zod";

/** One planned or applied Objective-C method signature. */
export const objcSignaturePlanItemSchema = z.strictObject({
  class_name: z.string().min(1),
  selector: z.string().min(1),
  method_type: z.enum(["instance", "class"]),
  implementation_address: z.string().nullable(),
  procedure: z.string().nullable(),
  type_encoding: z.string().nullable(),
  signature: z.string().nullable(),
  action: z.enum(["apply", "skip", "invalid"]),
  reason: z.string().nullable(),
});

/** Dry-run or applied Objective-C encodings as Ghidra function signatures. */
export const applyObjcSignaturesSchema = z.strictObject({
  applied: z.boolean(),
  plan: z.array(objcSignaturePlanItemSchema),
  results: z.record(z.string(), z.boolean()).nullable(),
  examined: z.number().int().min(0),
  apply_count: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type ApplyObjcSignatures = z.infer<typeof applyObjcSignaturesSchema>;
