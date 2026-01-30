import crypto from "crypto";

function makeNumericCode(input) {
  const hash = crypto.createHash("sha256").update(input).digest("hex"); // hex string
  const numbersOnly = hash.replace(/[a-f]/g, (c) => (parseInt(c, 16) % 10).toString()); // map letters to digits
  return numbersOnly.slice(0, 10); // first 10 digits
}

console.log(makeNumericCode("Trust2020")); // e.g. "7429356180"
