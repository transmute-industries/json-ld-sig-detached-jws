from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto.common import json_decode, json_encode


keys = {
    "publicKeyJwk": {
        "crv": "Ed25519",
        "x": "h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw",
        "kty": "OKP",
        "kid": "8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q"
    },
    "privateKeyJwk": {
        "crv": "Ed25519",
        "x": "h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw",
        "d": "Mqr_E4EQ51DxzVHh74HEy6F0JIykqDnrwgeJOxiLeTU",
        "kty": "OKP",
        "kid": "8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q"
    }
}


header = {
    "alg": "EdDSA",
    "b64": False,
    "crit": ["b64"]
}


payload = bytes.fromhex('4a4b4c')

s = jws.JWS(payload)
s.add_signature(jwk.JWK.from_json(json_encode(keys['privateKeyJwk'])),
                'EdDSA', json_encode(header))

jws = s.serialize(compact=True)


print(jws)
