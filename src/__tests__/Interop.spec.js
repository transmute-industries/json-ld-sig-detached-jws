const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;

const fixtures = require("../__fixtures__");

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../index");

describe.skip("Interop", () => {
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
    // input to sign: 65794a68624763694f694a465a45525451534973496d49324e4349365a6d467363325573496d4e79615851694f6c7369596a5930496c31392e efbfbdefbfbd795fefbfbd1cefbfbd76efbfbd6d560aefbfbd7befbfbd3fefbfbd173aefbfbd3defbfbd165115efbfbd72293e1038efbfbd14efbfbd5216350953efbfbd0b47d58a3cefbfbdefbfbd62efbfbd6befbfbd53efbfbdefbfbd53efbfbd25efbfbd4cefbfbdefbfbdefbfbd48efbfbd
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
