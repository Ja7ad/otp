const initWasm = require("./index");

jest.setTimeout(15000);

beforeAll(async () => {
  console.log("Starting WASM initialization...");
  await initWasm();
  console.log("WASM initialization complete");
});

describe("generateOTPURL", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const issuer = "TestIssuer";
  const accountName = "user@example.com";
  const digits = "6";
  const algo = "SHA1";

  test("generates valid TOTP URL", () => {
    const url = globalThis.generateOTPURL("totp", issuer, accountName, secret, digits, algo);
    console.log("TOTP URL:", url);
    expect(typeof url).toBe("string");
    expect(url).toMatch(/^otpauth:\/\/totp\//);
    expect(url).toContain(`issuer=${encodeURIComponent(issuer)}`);
    expect(url).toContain(`secret=${secret}`);
  });

  test("generates valid HOTP URL", () => {
    const url = globalThis.generateOTPURL("hotp", issuer, accountName, secret, digits, algo);
    console.log("HOTP URL:", url);
    expect(typeof url).toBe("string");
    expect(url).toMatch(/^otpauth:\/\/hotp\//);
    expect(url).toContain(`issuer=${encodeURIComponent(issuer)}`);
    expect(url).toContain(`secret=${secret}`);
    expect(url).toContain("counter=0");
  });

  test("returns error for missing args", () => {
    const result = globalThis.generateOTPURL("totp");
    console.log("Missing args result:", result);
    expect(result).toMatch(/^error:/);
  });

  test("returns error for unknown OTP type", () => {
    const result = globalThis.generateOTPURL("invalid", issuer, accountName, secret, digits, algo);
    console.log("Invalid type result:", result);
    expect(result).toMatch(/^error:/);
  });

  test("returns error for empty secret", () => {
    const result = globalThis.generateOTPURL("totp", issuer, accountName, "", digits, algo);
    console.log("Empty secret result:", result);
    expect(result).toMatch(/^error:.*secret/);
  });
});
