const fs = require("fs");
const path = require("path");
require("./wasm_exec.js");

const go = new Go();

/**
 * Initializes the WASM runtime and loads the OTP module.
 *
 * @returns {Promise<Object>} Resolves with an object containing available OTP functions from WASM:
 *  - generateHOTP(secret, counter, digits, algorithm)
 *  - generateTOTP(secret, timestamp, digits, algorithm)
 */
module.exports = async function initWasm() {
  const wasmPath = path.resolve(__dirname, "../lib/otp.wasm");
  const buffer = fs.readFileSync(wasmPath);

  const { instance } = await WebAssembly.instantiate(buffer, go.importObject);

  go.run(instance);

  return new Promise((resolve, reject) => {
    const checkReady = setInterval(() => {
      const hasExports =
        typeof globalThis.generateHOTP === "function" &&
        typeof globalThis.generateTOTP === "function";

      if (hasExports) {
        clearInterval(checkReady);
        console.log("✅ WASM OTP module loaded");

        resolve({
          /**
           * Generate an HOTP code using a shared secret and counter.
           *
           * @param {string} secret - Base32-encoded secret
           * @param {number} counter - Counter value (uint64)
           * @param {string} digits - "6", "8", or "10"
           * @param {string} algorithm - One of: "SHA1", "SHA256", "SHA512"
           * @returns {string} HOTP code or error string prefixed with "error:"
           */
          generateHOTP: globalThis.generateHOTP,

          /**
           * Validate a HOTP code using a shared secret and code.
           *
           * @param {string} secret - Base32-encoded secret
           * @param {string} code - Generated code by client app
           * @param {number} counter - Counter value (uint64)
           * @param {string} digits - "6", "8", or "10"
           * @param {string} algorithm - One of: "SHA1", "SHA256", "SHA512"
           * @param {number} skew - Skew is the allowed number of time steps (forward/backward) during TOTP validation
           * @returns {boolean} return ture/false for validate
           */
          validateHOTP: globalThis.validateHOTP,

          /**
           * Generate a TOTP code using a shared secret and timestamp.
           *
           * @param {string} secret - Base32-encoded secret
           * @param {number} timestamp - UNIX timestamp (int64)
           * @param {string} digits - "6", "8", or "10"
           * @param {string} algorithm - One of: "SHA1", "SHA256", "SHA512"
           * @param {number} period - Period time for generate code, default is 30
           * @returns {string} TOTP code or error string prefixed with "error:"
           */
          generateTOTP: globalThis.generateTOTP,

          /**
           * Validate a TOTP code using a shared secret and code.
           *
           * @param {string} secret - Base32-encoded secret
           * @param {string} code - Generated code by client app
           * @param {number} timestamp - UNIX timestamp (int64)
           * @param {string} digits - "6", "8", or "10"
           * @param {string} algorithm - One of: "SHA1", "SHA256", "SHA512"
           * @param {number} skew - Skew is the allowed number of time steps (forward/backward) during TOTP validation
           * @param {number} period - Period time for generate code, default is 30
           * @returns {boolean} return ture/false for validate
           */
          validateTOTP: globalThis.validateHOTP,

          /**
           * Generate an otpauth:// URL for TOTP or HOTP setup (e.g., for use with Google Authenticator).
           *
           * @param {string} otp - OTP type: "totp" or "hotp"
           * @param {string} issuer - Issuer name (e.g., "GitHub")
           * @param {string} accountName - Account identifier (e.g., "user@example.com")
           * @param {string} secret - Base32-encoded secret
           * @param {string} digits - Number of digits: "6", "8", or "10"
           * @param {string} algorithm - Hash algorithm: "SHA1", "SHA256", or "SHA512"
           * @returns {string} A valid otpauth:// URL or a string starting with "error:" on failure
           */
          generateOTPURL: globalThis.generateOTPURL,
        });
      }
    }, 10);

    setTimeout(() => {
      clearInterval(checkReady);
      reject(new Error("❌ WASM initialization timed out"));
    }, 5000);
  });
};
