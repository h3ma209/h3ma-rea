import { z } from "zod";

export const machoBindingSchema = z.strictObject({
  symbol: z.string(),
  address: z.string(),
  dylib: z.string().nullable(),
  kind: z.enum(["lazy", "non_lazy", "weak", "rebase"]),
});

export const inspectMachoBindingsResultSchema = z.strictObject({
  bindings: z.array(machoBindingSchema),
  total_bindings: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type InspectMachoBindingsResult = z.infer<
  typeof inspectMachoBindingsResultSchema
>;
