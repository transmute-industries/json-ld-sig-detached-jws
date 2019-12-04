const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;
const fixtures = require("../__fixtures__");

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../index");

describe("MyLinkedDataSignature2019", () => {
  it("sign and verify", async () => {
    const key = new MyLinkedDataKeyClass2019(fixtures.didKey);
    const signed = await jsigs.sign(fixtures.doc, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "MyLinkedDataSignature2019",
        linkedDataSignatureVerificationKeyType: "MyJwsVerificationKey2019",
        alg: "EdDSA",
        key,
        date: "2019-11-24T04:34:48Z"
      }),
      purpose: new AssertionProofPurpose(),
      compactProof: false
    });
    expect(signed.proof).toBeDefined();
    const res = await jsigs.verify(signed, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "MyLinkedDataSignature2019",
        linkedDataSignatureVerificationKeyType: "MyJwsVerificationKey2019",
        alg: "EdDSA",
        key
      }),
      purpose: new AssertionProofPurpose({
        controller: fixtures.didDoc
      }),
      compactProof: false
    });
    // console.log(res);
    const { verified } = res;
    expect(verified).toBe(true);
  });
});
