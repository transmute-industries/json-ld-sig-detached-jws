const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;

const fixtures = require("../__fixtures__");

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../index");

describe("Interop", () => {
  it("db sign / panva verify", async () => {
    const signed = await jsigs.sign(fixtures.doc, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "Ed25519Signature2018",
        linkedDataSignatureVerificationKeyType: "Ed25519VerificationKey2018",
        alg: "EdDSA",
        key: new MyLinkedDataKeyClass2019(fixtures.didKey),
        date: "2019-11-24T04:34:48Z"
      }),
      purpose: new AssertionProofPurpose(),
      compactProof: false
    });
    expect(signed.proof).toBeDefined();

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
