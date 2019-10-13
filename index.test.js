import {
  generateCryptoKeys,
  toPem,
  sign,
  generateSignKeys,
  Signature
} from "./index";

const privateStart = "-----BEGIN PRIVATE KEY-----";
const privateEnd = "-----END PRIVATE KEY-----";
const publicStart = "-----BEGIN PUBLIC KEY-----";
const publicEnd = "-----END PUBLIC KEY-----";

test("generateCryptoKeys()", async () => {
  const pair = await generateCryptoKeys();
  expect(pair.publicKey).toBeDefined();
  expect(pair.privateKey).toBeDefined();
});

test("toPEM()", async () => {
  const pair = await generateCryptoKeys();
  const { privateKey, publicKey } = await toPem(pair);
  expect(privateKey.substr(0, privateStart.length)).toEqual(privateStart);
  expect(privateKey.substr(privateKey.length - privateEnd.length)).toEqual(
    privateEnd
  );
  expect(publicKey.substr(0, publicStart.length)).toEqual(publicStart);
  expect(publicKey.substr(publicKey.length - publicEnd.length)).toEqual(
    publicEnd
  );
});

test("sign()", async () => {
  const pair = await generateSignKeys();
  const buf = str2ab("hello world!");
  const sig = await sign(pair.privateKey, buf);
  const str = sig.toString();
  const sig2 = Signature.from(str);
  expect(sig.toString()).toEqual(sig2.toString());
});

function str2ab(str) {
  var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  var bufView = new Uint8Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
