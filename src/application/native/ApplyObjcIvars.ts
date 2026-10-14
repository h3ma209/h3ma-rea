import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { applyObjcIvarsSchema } from "../../domain/native/objcIvarApply.js";
import { objcEncodingToCType } from "../../domain/native/objcTypeEncoding.js";
import { nativeDispatchMetadataResultSchema } from "../../domain/native/objcSwiftMetadata.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { inspectNativeDispatch } from "./NativeDispatchMetadataInspection.js";
import { nativeDispatchImplementationMapSchema } from "../../domain/native/nativeDispatchImplementationMap.js";
import { inspectNativeDispatchImplementations } from "./NativeDispatchImplementationMap.js";

const structureName = (className: string): string =>
  `rea_objc_${className.replace(/[^A-Za-z0-9_]+/gu, "_")}_ivar_layout`;

/** Plan or apply decoded Objective-C ivar layouts as Ghidra structures. */
export const applyObjcIvars = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.apply_objc_ivars>,
  signal?: AbortSignal,
): EnhancedResult => {
  const metadata = await inspectNativeDispatch(
    analysis,
    input.max_records,
    signal,
  );
  if (!metadata.ok) return metadata;
  const parsed = nativeDispatchMetadataResultSchema.safeParse(metadata.value);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "apply_objc_ivars",
        "dispatch metadata did not match the ivar-plan contract",
        { cause: parsed.error },
      ),
    );
  const ivars = parsed.data.result.objc_ivars.filter(
    (item) =>
      item.decode.status === "decoded" &&
      (input.class_name === undefined || item.class_name === input.class_name),
  );
  const byClass = new Map<string, typeof ivars>();
  for (const ivar of ivars) {
    const bucket = byClass.get(ivar.class_name) ?? [];
    bucket.push(ivar);
    byClass.set(ivar.class_name, bucket);
  }
  const limitations: string[] = [];
  const implementations = await inspectNativeDispatchImplementations(
    analysis,
    {
      max_records: input.max_records,
      resolve_procedures: true,
      ...(input.class_name === undefined ? {} : { class_name: input.class_name }),
    },
    signal,
  );
  const procedureForClass = new Map<string, string>();
  if (implementations.ok) {
    const joined = nativeDispatchImplementationMapSchema.safeParse(
      implementations.value,
    );
    if (joined.success) {
      for (const item of joined.data.items) {
        if (
          item.procedure?.found === true &&
          !procedureForClass.has(item.class_name)
        )
          procedureForClass.set(item.class_name, item.procedure.address);
      }
    } else limitations.push("Implementation map could not be parsed for class anchors.");
  }
  const classes = [...byClass.keys()].slice(0, input.max_classes);
  const truncated = byClass.size > classes.length;
  const plan = classes.map((class_name) => {
    const rows = byClass.get(class_name) ?? [];
    const fields = [];
    for (const ivar of rows) {
      if (ivar.offset === null) continue;
      const data_type =
        ivar.type_encoding === null
          ? null
          : objcEncodingToCType(ivar.type_encoding);
      if (data_type === null) continue;
      fields.push({
        name: ivar.name,
        offset: ivar.offset,
        data_type,
        type_encoding: ivar.type_encoding,
      });
    }
    fields.sort((left, right) => left.offset - right.offset);
    const procedure = procedureForClass.get(class_name) ?? null;
    if (fields.length === 0)
      return {
        class_name,
        structure_name: structureName(class_name),
        procedure,
        fields: [],
        size_bytes: null,
        action: "invalid" as const,
        reason: "No ivar had both a resolved offset and a supported type encoding.",
      };
    if (procedure === null)
      return {
        class_name,
        structure_name: structureName(class_name),
        procedure: null,
        fields,
        size_bytes: Math.max(
          ...fields.map(
            (field) =>
              field.offset +
              (rows.find((row) => row.name === field.name)?.size ?? 1),
          ),
        ),
        action: "skip" as const,
        reason: "No containing procedure was resolved for this class.",
      };
    return {
      class_name,
      structure_name: structureName(class_name),
      procedure,
      fields,
      size_bytes: Math.max(
        ...fields.map(
          (field) =>
            field.offset +
            (rows.find((row) => row.name === field.name)?.size ?? 1),
        ),
      ),
      action: "apply" as const,
      reason: null,
    };
  });
  const eligible = plan.filter((item) => item.action === "apply");
  if (implementations.ok) {
    const joined = nativeDispatchImplementationMapSchema.safeParse(
      implementations.value,
    );
    if (joined.success) limitations.push(...joined.data.limitations);
  }
  if (truncated)
    limitations.push("Class budget max_classes was reached before every decoded class.");
  if (!input.apply || eligible.length === 0)
    return ok(
      jsonValueSchema.parse(
        applyObjcIvarsSchema.parse({
          applied: false,
          plan,
          results: null,
          examined: plan.length,
          apply_count: eligible.length,
          limitations:
            input.apply && eligible.length === 0
              ? [...limitations, "No ivar layouts were eligible to apply."]
              : limitations,
        }),
      ),
    );
  const results: Record<string, boolean> = {};
  for (const item of eligible) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("apply_objc_ivars"));
    const applied = await analysis.execute(
      "annotate_native_function",
      {
        procedure: item.procedure!,
        structures: [
          {
            name: item.structure_name,
            ...(item.size_bytes === null ? {} : { size: item.size_bytes }),
            fields: item.fields.map((field) => ({
              name: field.name,
              offset: field.offset,
              data_type: field.data_type,
            })),
          },
        ],
      },
      signal === undefined ? {} : { signal },
    );
    results[item.class_name] = applied.ok;
    if (!applied.ok) limitations.push(applied.error.message);
  }
  return ok(
    jsonValueSchema.parse(
      applyObjcIvarsSchema.parse({
        applied: true,
        plan,
        results,
        examined: plan.length,
        apply_count: eligible.length,
        limitations,
      }),
    ),
  );
};
