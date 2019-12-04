const jose = require("@panva/jose");
const base64url = require("base64url");

const fixtures = require("../__fixtures__");

const header = {
  alg: "EdDSA",
  b64: false,
  crit: ["b64"]
};

const toBeSigned = Buffer.from("1223123123123123123", "hex");

describe("EdDSA", () => {
  it("sign and verify", async () => {
    const flat = jose.JWS.sign.flattened(
      toBeSigned,
      jose.JWK.asKey(fixtures.didKey.privateKeyJwk),
      header
    );
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
