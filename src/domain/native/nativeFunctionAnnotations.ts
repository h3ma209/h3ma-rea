import { z } from "zod";
import { functionDossierSchema } from "../hopperValues.js";

const localAnnotationSchema = z.strictObject({
  current_name: z.string().min(1),
  name: z.string().min(1).optional(),
  data_type: z.string().min(1).optional(),
});

const structureFieldSchema = z.strictObject({
  name: z.string().min(1),
  offset: z.number().int().min(0),
  data_type: z.string().min(1),
  length: z.number().int().min(1).optional(),
});

const structureAnnotationSchema = z.strictObject({
  name: z.string().min(1),
  size: z.number().int().min(0).optional(),
  fields: z.array(structureFieldSchema).min(1),
});

/** One explicit function's analyst-authored metadata changes. */
export const nativeFunctionAnnotationsInputSchema = z
  .strictObject({
    procedure: z.string().min(1),
    name: z.string().min(1).optional(),
    comment: z
      .string()
      .optional()
      .describe("Regular entry comment; empty text clears it"),
    inline_comment: z
      .string()
      .optional()
      .describe("Inline entry comment; empty text clears it"),
    signature: z
      .string()
      .min(1)
      .optional()
      .describe("Ghidra C-like function signature applied to this function"),
    locals: z
      .array(localAnnotationSchema)
      .min(1)
      .optional()
      .describe("Rename or retype existing local variables by current name"),
    structures: z
      .array(structureAnnotationSchema)
      .min(1)
      .optional()
      .describe("Create or replace session-database structures"),
  })
  .refine(
    (value) =>
      value.name !== undefined ||
      value.comment !== undefined ||
      value.inline_comment !== undefined ||
      value.signature !== undefined ||
      value.locals !== undefined ||
      value.structures !== undefined,
    "Supply at least one annotation change",
  )
  .refine(
    (value) =>
      (value.locals ?? []).every(
        (local) => local.name !== undefined || local.data_type !== undefined,
      ),
    "Each local change supplies a name and/or data type",
  );

/** Readback and refreshed analysis after one atomic metadata edit. */
export const nativeFunctionAnnotationsSchema = z
  .strictObject({
    annotations: z.strictObject({
      address: z.string().min(1),
      name: z.string().min(1),
      comment: z.string().nullable(),
      inline_comment: z.string().nullable(),
      signature: z.string().nullable().default(null),
      locals: z
        .array(
          z.strictObject({
            name: z.string().min(1),
            data_type: z.string().nullable(),
            storage: z.string().nullable(),
          }),
        )
        .default([]),
      structures: z
        .array(
          z.strictObject({
            name: z.string().min(1),
            path: z.string().min(1),
            size_bytes: z.number().int().nullable(),
          }),
        )
        .default([]),
    }),
    dossier: functionDossierSchema,
    effects: z.strictObject({
      scope: z.literal("session-analysis-database"),
      source_bytes_modified: z.literal(false),
      persists_after_close: z.literal(false),
    }),
  })
  .superRefine((value, context) => {
    if (
      value.annotations.address !== value.dossier.procedure.address ||
      value.annotations.name !== value.dossier.procedure.name
    )
      context.addIssue({
        code: "custom",
        message:
          "Annotation readback disagrees with refreshed function identity",
      });
  });
