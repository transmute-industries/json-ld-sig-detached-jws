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
  it("panva sign / db verify", async () => {
    const signed1 = await jsigs.sign(
      { ...fixtures.doc },
      {
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
      }
    );
    expect(signed1.proof).toBeDefined();
    const signed2 = await jsigs.sign(
      { ...fixtures.doc },
      {
        suite: new Ed25519Signature2018({
          verificationMethod: fixtures.didKey.id,
          key: new Ed25519KeyPair(fixtures.didKey),
          date: "2019-11-24T04:34:48Z"
        }),
        purpose: new AssertionProofPurpose(),
        compactProof: false
      }
    );

    expect(signed1.proof.jws).toEqual(signed2.proof.jws);

    // https://github.com/panva/jose/blob/master/lib/jws/sign.js#L106
    // input to sign: 65794a68624763694f694a465a45525451534973496d49324e4349365a6d467363325573496d4e79615851694f6c7369596a5930496c31392e 7476643558373463753361516256594b3848766a503977584f754d3969525a52466546794b5434514f4a5555683149574e516c546941744831596f38367342697832757055366d455534456c6b6b792d6f644a496a67
    // input to sign: 65794a68624763694f694a465a45525451534973496d49324e4349365a6d467363325573496d4e79615851694f6c7369596a5930496c31392e b6f7795fbe1cbb76906d560af07be33fdc173ae33d89165115e172293e10389514875216350953880b47d58a3ceac062c76ba953a984538125924cbea1d2488e
    // https://github.com/digitalbazaar/crypto-ld/blob/master/lib/Ed25519KeyPair.js#L468

    // const res = await jsigs.verify(signed, {
    //   suite: new Ed25519Signature2018({
    //     verificationMethod: fixtures.didKey.id,
    //     key: new Ed25519KeyPair(fixtures.didKey)
    //   }),
    //   purpose: new AssertionProofPurpose({
    //     controller: fixtures.didDoc
    //   }),
    //   compactProof: false
    // });
    // expect(res.verified).toBe(true);
  });
});
