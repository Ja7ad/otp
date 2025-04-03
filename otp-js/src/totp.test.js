const initWasm = require("./index");

jest.setTimeout(15000); // Extend timeout for WASM init

beforeAll(async () => {
  console.log("Starting WASM initialization...");
  await initWasm(); // Initializes runtime and registers global functions
  console.log("WASM initialization complete");
});

describe("generateTOTP", () => {
  test("returns valid OTP with realistic timestamp", () => {
    const timestamp = 1698710400; // 2023-10-31 00:00:00 UTC
    const code = globalThis.generateTOTP("JBSWY3DPEHPK3PXP", timestamp, "6", "SHA1", 30);
    console.log("Generated TOTP:", code);
    expect(code).toMatch(/^\d{6}$/);
  });

  test("returns error with invalid secret", () => {
    const timestamp = 1698710400;
    const result = globalThis.generateTOTP("!!!invalid", timestamp, "6", "SHA1", 30);
    console.log("Result with invalid input:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error: invalid secret/);
  });

  test("returns valid OTP for 9 digits", () => {
    const timestamp = 1698710400;
    const result = globalThis.generateTOTP("JBSWY3DPEHPK3PXP", timestamp, "9", "SHA1", 30);
    console.log("Result with 9 digits:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^\d{9}$/);
  });

  test("returns error with negative timestamp", () => {
    const result = globalThis.generateTOTP("JBSWY3DPEHPK3PXP", -1, "6", "SHA1", 30);
    console.log("Result with negative timestamp:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error: timestamp must be non-negative/);
  });
});

describe("validateTOTP", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const digits = "6";
  const algo = "SHA1";
  const period = 30;
  const skew = 1; // ✅ valid skew between 0 and 10

  test("returns true for valid TOTP code", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const code = globalThis.generateTOTP(secret, timestamp, digits, algo, period);
    console.log("Generated TOTP:", code);

    const result = globalThis.validateTOTP(secret, code, timestamp, digits, algo, skew, period);
    expect(result).toBe(true); // ✅ expecting true
  });

  test("returns false for invalid TOTP code", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const result = globalThis.validateTOTP(secret, "000000", timestamp, digits, algo, skew, period);
    expect(result).toBe(false); // ✅ expecting false
  });

  test("returns error for invalid secret", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const result = globalThis.validateTOTP("!!!bad", "123456", timestamp, digits, algo, skew, period);
    console.log("Invalid secret result:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error:/);
  });

  test("returns error for negative timestamp", () => {
    const result = globalThis.validateTOTP(secret, "123456", -1, digits, algo, skew, period);
    console.log("Negative timestamp result:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error:/);
  });

  test("returns error for invalid skew", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const invalidSkew = -1; // ❌ invalid
    const result = globalThis.validateTOTP(secret, "123456", timestamp, digits, algo, invalidSkew, period);
    console.log("Invalid skew result:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error:/);
  });
});
