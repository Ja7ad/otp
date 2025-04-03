const initWasm = require("./index");

jest.setTimeout(15000);

beforeAll(async () => {
  console.log("Starting WASM initialization...");
  await initWasm();
  console.log("WASM initialization complete");
});

test("generateHOTP returns valid OTP", () => {
  const code = globalThis.generateHOTP("JBSWY3DPEHPK3PXP", 0, "6", "SHA1");
  console.log("Generated HOTP:", code);
  expect(code).toMatch(/^\d{6}$/);
});

test("generateHOTP with wrong input returns error", () => {
  const result = globalThis.generateHOTP("!!!invalid", 0, "6", "SHA1");
  console.log("Result with invalid input:", result);
  expect(typeof result).toBe("string");
  expect(result.startsWith("error:")).toBe(true);
});

describe("validateHOTP", () => {
  test("returns true for correct HOTP code", () => {
    const secret = "JBSWY3DPEHPK3PXP"; // Base32 for "Hello!"
    const counter = 0;
    const digits = "6";
    const algo = "SHA1";
    const skew = 1;

    const code = globalThis.generateHOTP(secret, counter, digits, algo);
    console.log("Generated HOTP:", code);

    const isValid = globalThis.validateHOTP(secret, code, counter, digits, algo, skew);
    expect(isValid).toBe(true);
  });

  test("returns false for wrong HOTP code", () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const counter = 0;
    const digits = "6";
    const algo = "SHA1";
    const skew = 1;

    const isValid = globalThis.validateHOTP(secret, "999999", counter, digits, algo, skew);
    expect(isValid).toBe(false);
  });

  test("returns error with invalid secret", () => {
    const result = globalThis.validateHOTP("!!!bad", "123456", 0, "6", "SHA1", 1);
    console.log("Invalid secret result:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error:/);
  });

  test("returns error with invalid skew", () => {
    const result = globalThis.validateHOTP("JBSWY3DPEHPK3PXP", "123456", 0, "6", "SHA1", -1);
    console.log("Invalid skew result:", result);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/^error:/);
  });
});