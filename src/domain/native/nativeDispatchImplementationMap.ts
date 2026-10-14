import { z } from "zod";

import {
  nativeMetadataDecodeSchema,
  objcDispatchImplementationSchema,
} from "./objcSwiftMetadata.js";

/** One class/selector/implementation row joined to a containing procedure. */
export const nativeDispatchImplementationMapItemSchema = z.strictObject({
  class_name: z.string().min(1),
  selector: z.string().min(1),
  method_type: z.enum(["instance", "class"]),
  category: z.string().nullable(),
  implementation_address: z.string().nullable(),
  type_encoding: z.string().nullable().default(null),
  decode: nativeMetadataDecodeSchema,
  procedure: z
    .discriminatedUnion("found", [
      z.strictObject({
        found: z.literal(true),
        address: z.string().min(1),
        name: z.string().nullable(),
      }),
      z.strictObject({
        found: z.literal(false),
        address: z.null(),
        name: z.null(),
        reason: z.enum([
          "outside_segments",
          "not_in_procedure",
          "implementation_unmapped",
          "not_requested",
        ]),
      }),
    ])
    .nullable(),
});

/** Joined Objective-C/Swift dispatch map for one Mach-O image. */
export const nativeDispatchImplementationMapSchema = z.strictObject({
  items: z.array(nativeDispatchImplementationMapItemSchema),
  total: z.number().int().min(0),
  returned: z.number().int().min(0),
  exhaustive: z.boolean(),
  limitations: z.array(z.string()),
});

export type NativeDispatchImplementationMap = z.infer<
  typeof nativeDispatchImplementationMapSchema
>;

/** Project a decoded implementation row into the map item without procedure join. */
export const dispatchImplementationWithoutProcedure = (
  implementation: z.infer<typeof objcDispatchImplementationSchema>,
  resolveProcedures: boolean,
): z.infer<typeof nativeDispatchImplementationMapItemSchema> => ({
  class_name: implementation.class_name,
  selector: implementation.selector,
  method_type: implementation.method_type,
  category: implementation.category ?? null,
  implementation_address: implementation.implementation_address,
  type_encoding: implementation.type_encoding,
  decode: implementation.decode,
  procedure:
    resolveProcedures === false
      ? {
          found: false,
          address: null,
          name: null,
          reason: "not_requested",
        }
      : implementation.implementation_address === null
        ? {
            found: false,
            address: null,
            name: null,
            reason: "implementation_unmapped",
          }
        : null,
});
