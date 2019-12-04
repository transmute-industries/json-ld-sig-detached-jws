const jsigs = require("jsonld-signatures");
const { AssertionProofPurpose } = jsigs.purposes;
const { Ed25519KeyPair } = require("crypto-ld");
const { Ed25519Signature2018 } = jsigs.suites;

const doc = {
  "@context": {
    schema: "http://schema.org/",
    name: "schema:name",
    homepage: "schema:url",
    image: "schema:image"
  },
  name: "Manu Sporny",
  homepage: "https://manu.sporny.org/",
  image: "https://manu.sporny.org/images/manu.png"
};

const privateKeyJwk = {
  crv: "Ed25519",
  x: "VQ99N9eEYrkt9d7Iw-sq9tAbB7H_vX82iCNU4uBDYwA",
  d: "Sexnoz1MarNT4lu88ufi_T4G57d4bekfg8m18uYHQ4g",
  kty: "OKP",
  kid: "YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
};

const publicKeyJwk = {
  crv: "Ed25519",
  x: "VQ99N9eEYrkt9d7Iw-sq9tAbB7H_vX82iCNU4uBDYwA",
  kty: "OKP",
  kid: "YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
};

const didKeypair = {
  passphrase: null,
  id:
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU",
  controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  type: "Ed25519VerificationKey2018",
  privateKeyJwk,
  publicKeyJwk,
  privateKeyBase58:
    "55dKnusKVZjGK9rtTQgT3usTnALuChkzQpoksz4jES5G7AKMCpQCBt3azfko5oTMQD11gPxQ1bFRAYWSwcYSPdPV",
  publicKeyBase58: "25C16YaTbD96wAvdokKnTmD8ruWvYARDkc6nfNEA3L71"
};

const didKeyDoc = {
  "@context": "https://w3id.org/did/v1",
  id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  publicKey: [
    {
      id:
        "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU",
      type: "Ed25519VerificationKey2018",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyJwk,
      privateKeyBase58: didKeypair.privateKeyBase58
    }
  ],
  authentication: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
  ],
  assertionMethod: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
  ],
  capabilityDelegation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
  ],
  capabilityInvocation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#YDTVGm77-bIReuTAVmFnAdkpMWpuvM74wG6vAhfBYmU"
  ],
  keyAgreement: [
    {
      id:
        "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#zCDHgu3FAkC7ugAMPB7UMjMssNx6XXFnWFJXF6FYU98CLH",
      type: "X25519KeyAgreementKey2019",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyBase58: "DnyBg4MYpNdF4JQihynmCiC5hpiZh5tkQdx4QTfk1xE5"
    }
  ]
};

const {
  MyLinkedDataKeyClass2019,
  MyLinkedDataSignature2019
} = require("../index");

describe("Interop", () => {
  it("sign and verify", async () => {
    const signed = await jsigs.sign(doc, {
      suite: new MyLinkedDataSignature2019({
        LDKeyClass: MyLinkedDataKeyClass2019,
        linkedDataSigantureType: "Ed25519Signature2018",
        linkedDataSignatureVerificationKeyType: "Ed25519VerificationKey2018",
        alg: "EdDSA",
        key: new MyLinkedDataKeyClass2019(didKeypair),
        date: "2019-11-24T04:34:48Z"
      }),
      purpose: new AssertionProofPurpose(),
      compactProof: false
    });
    expect(signed.proof).toBeDefined();

    const res = await jsigs.verify(signed, {
      suite: new Ed25519Signature2018({
        verificationMethod: didKeypair.id,
        key: new Ed25519KeyPair(didKeypair)
      }),
      purpose: new AssertionProofPurpose({
        controller: didKeyDoc
      }),
      compactProof: false
    });
    expect(res.verified).toBe(true);
  });
});
