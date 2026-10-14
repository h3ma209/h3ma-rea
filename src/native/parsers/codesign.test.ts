import { describe, expect, it } from "vitest";

import { parseCodeSignature, parseEntitlements } from "./codesign.js";

describe("parseEntitlements", () => {
  it("parses codesign XML entitlements from stdout", () => {
    const parsed = parseEntitlements(
      'Executable=/tmp/app\n<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>\n',
    );
    expect(parsed).toEqual({
      value: { "com.apple.security.app-sandbox": true },
      omittedPrototypeKeys: 0,
    });
  });

  it("returns null when codesign printed no entitlements plist", () => {
    expect(parseEntitlements("Executable=/tmp/app\n")).toEqual({
      value: null,
      omittedPrototypeKeys: 0,
    });
  });
});

describe("parseCodeSignature", () => {
  it("keeps display identity separate from entitlement capture", () => {
    const parsed = parseCodeSignature(
      "Identifier=com.example.fixture\nFormat=Mach-O thin (arm64)\nTeamIdentifier=not set\nCodeDirectory v=20400 size=342 flags=0x10000(runtime) hashes=2+2\n",
      false,
    );
    expect(parsed.entitlements).toBeNull();
    expect(parsed.hardened_runtime).toBe(true);
    expect(parsed.limitations).toEqual([
      "Display identity comes from codesign -d --verbose=4. Designated requirements and entitlements are captured by separate bounded commands.",
    ]);
  });
});
