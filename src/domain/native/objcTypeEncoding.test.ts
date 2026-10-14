import { describe, expect, it } from "vitest";

import { objcEncodingToSignature } from "./objcTypeEncoding.js";

describe("objcEncodingToSignature", () => {
  it("translates a void instance method", () => {
    expect(objcEncodingToSignature("v24@0:8", "buildTapped:")).toBe(
      "void buildTapped_(void * self, void * cmd)",
    );
  });

  it("translates integer, pointer, and object arguments", () => {
    expect(objcEncodingToSignature("i32@0:8*16@24", "set:value:")).toBe(
      "int set_value_(void * self, void * cmd, char * arg2, void * arg3)",
    );
  });

  it("rejects struct and unknown encodings", () => {
    expect(objcEncodingToSignature("v16@0:8{CGRect=ffff}16", "draw:")).toBe(
      null,
    );
    expect(objcEncodingToSignature("?16@0:8", "block")).toBeNull();
  });
});
