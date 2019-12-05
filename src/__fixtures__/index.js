const { Ed25519KeyPair } = require("crypto-ld");
const { keyToDidDoc } = require("did-method-key").driver();

const utils = require("../utils");

// const keypair = crypto.generateKeyPairSync("ed25519", {
//   publicKeyEncoding: { format: "pem", type: "spki" },
//   privateKeyEncoding: { format: "pem", type: "pkcs8" }
// });

const publicKeyPem =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAh83ufcOAO9zVigHCgOOTp8waN/ycH4xnPRvn45yu6gw=\n" +
  "-----END PUBLIC KEY-----\n";

const privateKeyPem =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MC4CAQAwBQYDK2VwBCIEIDKq/xOBEOdQ8c1R4e+BxMuhdCSMpKg568IHiTsYi3k1\n" +
  "-----END PRIVATE KEY-----\n";

const publicKeyBase58 = utils.publicKeyPemToPublicKeyBase58(publicKeyPem);
const privateKeyBase58 = utils.privateKeyPemToPrivateKeyBase58({
  publicKeyPem,
  privateKeyPem
});

const publicKeyJwk = utils.publicKeyBase58ToPublicKeyJwk(publicKeyBase58);
const privateKeyJwk = utils.privateKeyBase58ToPrivateKeyJwk(privateKeyBase58);

console.log(JSON.stringify({ publicKeyJwk, privateKeyJwk }, null, 2));

const didKey = new Ed25519KeyPair({ publicKeyBase58, privateKeyBase58 });

didKey.publicKeyJwk = publicKeyJwk;
didKey.privateKeyJwk = privateKeyJwk;

let didDoc = keyToDidDoc(didKey);

didKey.owner = didDoc.id;
didKey.controller = didDoc.id;
didKey.id = didDoc.id + "#" + publicKeyJwk.kid;

didDoc = keyToDidDoc(didKey);
didDoc.capabilityInvocation = [didKey.id];
didDoc.capabilityDelegation = [didKey.id];
didDoc.assertionMethod = [didKey.id];
didDoc.authentication = [didKey.id];

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

module.exports = {
  didKey,
  didDoc,
  doc
};
