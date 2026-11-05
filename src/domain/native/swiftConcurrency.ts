import { z } from "zod";

export const swiftActorSchema = z.strictObject({
  name: z.string().min(1),
  mangled_name: z.string().min(1),
  address: z.string().nullable(),
  isolated_methods: z.array(z.string()),
});

export const swiftAsyncFunctionSchema = z.strictObject({
  name: z.string().min(1),
  mangled_name: z.string().min(1),
  entry_address: z.string().nullable(),
  continuation_points: z.array(z.string()),
  kind: z.enum(["async_function", "async_closure", "task_creator", "unknown"]),
});

export const inspectSwiftConcurrencyResultSchema = z.strictObject({
  actors: z.array(swiftActorSchema),
  async_functions: z.array(swiftAsyncFunctionSchema),
  total_concurrency_symbols: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type InspectSwiftConcurrencyResult = z.infer<
  typeof inspectSwiftConcurrencyResultSchema
>;

/** Classify Swift concurrency symbol mangling patterns. */
export const classifySwiftConcurrencySymbol = (
  name: string,
): {
  isConcurrency: boolean;
  kind: "actor" | "async_function" | "async_closure" | "task_creator" | null;
} => {
  // Swift concurrency symbols typically contain:
  // Tu: async function completion handler / continuation
  // TYa: async function resume / entry
  // ScA: Actor protocol conformance / witness
  // ScT: Task structure creation
  // ScG: TaskGroup
  if (name.includes("ScA") || name.includes("Actor")) {
    return { isConcurrency: true, kind: "actor" };
  }
  if (name.includes("Tu") || name.includes("TYa")) {
    return { isConcurrency: true, kind: "async_function" };
  }
  if (name.includes("ScT") || name.includes("task_create")) {
    return { isConcurrency: true, kind: "task_creator" };
  }
  if (
    name.includes("async") ||
    (name.includes("closure") && name.includes("Tu"))
  ) {
    return { isConcurrency: true, kind: "async_closure" };
  }
  return { isConcurrency: false, kind: null };
};
