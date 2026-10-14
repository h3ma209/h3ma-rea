import { z } from "zod";

/** One static reference to an Objective-C selector name. */
export const objcSelectorRefSchema = z.strictObject({
  selector: z.string().min(1),
  class_name: z.string().min(1).nullable(),
  selector_address: z.string().nullable(),
  reference_address: z.string().min(1),
  procedure: z.string().nullable(),
  basis: z.enum(["selector_address_xref", "selector_string_xref"]),
});

/** Selector reference sites joined from metadata and provider xrefs. */
export const inspectObjcSelectorRefsSchema = z.strictObject({
  refs: z.array(objcSelectorRefSchema),
  examined_selectors: z.number().int().min(0),
  exhaustive: z.boolean(),
  limitations: z.array(z.string()),
});

export type InspectObjcSelectorRefs = z.infer<typeof inspectObjcSelectorRefsSchema>;
