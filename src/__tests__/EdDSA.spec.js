const jose = require("@panva/jose");
const base64url = require("base64url");

const fixtures = require("../__fixtures__");

const header = {
  alg: "EdDSA",
  b64: false,
  crit: ["b64"]
};

const toBeSigned = Buffer.from("4a4b4c", "hex");
// const toBeSigned = "test";

describe("EdDSA", () => {
  it("sign and verify", async () => {
    const flat = jose.JWS.sign.flattened(
      toBeSigned,
      jose.JWK.asKey(fixtures.didKey.privateKeyJwk),
      header
    );
    // console.log(`${flat.protected}.${flat.payload}.${flat.signature}`);
    const verified = await jose.JWS.verify(
      {
        ...flat,
        payload: toBeSigned.toString()
      },
      jose.JWK.asKey(fixtures.didKey.publicKeyJwk),
      {
        crit: ["b64"]
      }
    );
    expect(verified).toBe(toBeSigned.toString());
  });
});
