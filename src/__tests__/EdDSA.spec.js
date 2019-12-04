const jose = require("@panva/jose");
const base64url = require("base64url");

const fixtures = require("../__fixtures__");

const header = {
  alg: "EdDSA",
  b64: false,
  crit: ["b64"]
};
const toBeSigned = Buffer.from(base64url.encode("123"));

describe("EdDSA", () => {
  it("sign and verify", async () => {
    const jws = jose.JWS.sign(
      toBeSigned,
      jose.JWK.asKey(fixtures.didKey.privateKeyJwk),
      header
    );
    const verified = await jose.JWS.verify(
      jws,
      jose.JWK.asKey(fixtures.didKey.publicKeyJwk),
      {
        crit: ["b64"]
      }
    );
    expect(verified).toBe("MTIz");
  });

  it("flattened sign and verify", async () => {
    const flat = jose.JWS.sign.flattened(
      toBeSigned,
      jose.JWK.asKey(fixtures.didKey.privateKeyJwk),
      header
    );
    const jws = `${flat.protected}.${flat.payload}.${flat.signature}`;
    const verified = await jose.JWS.verify(
      jws,
      jose.JWK.asKey(fixtures.didKey.publicKeyJwk),
      {
        crit: ["b64"]
      }
    );
    expect(verified).toBe("MTIz");
  });
});
