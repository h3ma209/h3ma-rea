import { z } from "zod";

/** One static call site inside a single procedure. */
export const functionCallSiteSchema = z.strictObject({
  address: z.string().min(1),
  status: z.enum([
    "direct",
    "resolved-indirect",
    "ambiguous",
    "unresolved",
    "not-call",
    "unavailable",
  ]),
  mechanism: z.enum(["direct", "computed", "indirect", "unavailable"]),
  basis: z.enum([
    "provider-reference",
    "objc-metadata",
    "swift-dispatch-slot",
  ]),
  targets: z.array(
    z.strictObject({
      address: z.string().min(1),
      procedure: z.string().nullable(),
      status: z.enum(["direct", "resolved-indirect", "candidate"]),
      basis: z.enum([
        "provider-reference",
        "objc-metadata",
        "swift-dispatch-slot",
      ]),
      selector: z.string().nullable(),
      class_name: z.string().nullable(),
    }),
  ),
  limitations: z.array(z.string()),
});

/** Every call site in one procedure, with metadata joins kept explicit. */
export const functionCallResolutionSchema = z.strictObject({
  procedure: z.string().min(1),
  sites: z.array(functionCallSiteSchema),
  examined: z.number().int().min(0),
  exhaustive: z.boolean(),
  limitations: z.array(z.string()),
});

export type FunctionCallResolution = z.infer<
  typeof functionCallResolutionSchema
>;
