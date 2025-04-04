const Benchmark = require("benchmark");
const initWasm = require("./index");

(async () => {
  const wasm = await initWasm();

  const secret = "JBSWY3DPEHPK3PXP";
  const digits = "6";
  const counter = 0;
  const algorithms = ["SHA1", "SHA256", "SHA512"];

  algorithms.forEach((algo) => {
    const result = wasm.generateHOTP(secret, counter, digits, algo);
    console.log(`→ ${algo}: ${result}`);
  });

  global.gc?.();
  const memoryBefore = process.memoryUsage().heapUsed;

  const suite = new Benchmark.Suite();

  algorithms.forEach((algo) => {
    suite.add(`generateHOTP/${algo}`, () => {
      const result = wasm.generateHOTP(secret, counter, digits, algo);
      if (typeof result !== "string" || result.startsWith("error:")) {
        throw new Error(`Failed to generate HOTP with ${algo}: ${result}`);
      }
    });
  });

  suite
    .on("start", () => {
      console.log("\n🏁 Starting HOTP benchmarks...\n");
    })
    .on("cycle", (event) => {
      console.log(String(event.target));
    })
    .on("complete", function () {
      global.gc?.();
      const memoryAfter = process.memoryUsage().heapUsed;
      const memoryDiffKB = (memoryAfter - memoryBefore) / 1024;
      console.log(`\n🔍 Memory used: ~${memoryDiffKB.toFixed(2)} KB`);
      console.log(`🚀 Fastest is ${this.filter("fastest").map("name")}`);
    })
    .run({ async: true });
})();
