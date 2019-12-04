const jsigs = require("jsonld-signatures");
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;
const { AssertionProofPurpose } = jsigs.purposes;

const fixtures = require("../__fixtures__");

describe("Ed25519Signature2018", () => {
  it("sign and verify", async () => {
    const signed = await jsigs.sign(fixtures.doc, {
      suite: new Ed25519Signature2018({
        verificationMethod: fixtures.didKey.id,
        key: new Ed25519KeyPair(fixtures.didKey),
        date: "2019-11-24T04:34:48Z"
      }),
      purpose: new AssertionProofPurpose(),
      compactProof: false
    });
    const res = await jsigs.verify(signed, {
      suite: new Ed25519Signature2018({
        verificationMethod: fixtures.didKey.id,
        key: new Ed25519KeyPair(fixtures.didKey)
      }),
      purpose: new AssertionProofPurpose({
        controller: fixtures.didDoc
      }),
      compactProof: false
    });
    expect(res.verified).toBe(true);
  });
});
