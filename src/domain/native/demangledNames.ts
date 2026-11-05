import { z } from "zod";

/** One planned or applied demangle rename. */
export const demangledNamePlanItemSchema = z.strictObject({
  address: z.string().min(1),
  current_name: z.string().min(1),
  demangled: z.string().nullable(),
  action: z.enum(["rename", "skip", "invalid"]),
  reason: z.string().nullable(),
});

/** Dry-run or applied bulk rename from Swift demangle results. */
export const applyDemangledNamesSchema = z.strictObject({
  applied: z.boolean(),
  plan: z.array(demangledNamePlanItemSchema),
  results: z.record(z.string(), z.boolean()).nullable(),
  examined: z.number().int().min(0),
  rename_count: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type ApplyDemangledNames = z.infer<typeof applyDemangledNamesSchema>;

const SWIFT_MANGLE = /(?:^|_)(\$s|\$S|\$T)/u;

/** True when a provider name still carries a Swift mangled encoding. */
export const isSwiftMangledName = (name: string): boolean =>
  SWIFT_MANGLE.test(name);
