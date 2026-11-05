import { z } from "zod";

export const symbolDeltaSchema = z.strictObject({
  name: z.string(),
  change: z.enum(["added", "removed", "modified_address"]),
  baseline_address: z.string().nullable(),
  target_address: z.string().nullable(),
});

export const stringDeltaSchema = z.strictObject({
  value: z.string(),
  change: z.enum(["added", "removed"]),
});

export const diffBinaryRevisionsResultSchema = z.strictObject({
  symbol_differences: z.array(symbolDeltaSchema),
  string_differences: z.array(stringDeltaSchema),
  summary: z.strictObject({
    symbols_added: z.number().int().min(0),
    symbols_removed: z.number().int().min(0),
    strings_added: z.number().int().min(0),
    strings_removed: z.number().int().min(0),
  }),
  limitations: z.array(z.string()),
});

export type DiffBinaryRevisionsResult = z.infer<
  typeof diffBinaryRevisionsResultSchema
>;
