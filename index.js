import { subtle } from "isomorphic-webcrypto";

/**
 * @name generateCryptoKeys
 * @desc Generates a pair of keys to encrypt/decrypt data.
 * @param {number} bits
 * @param {string} hash SHA-256 or SHA-512
 * @returns {Promise<CryptoKeyPair>}
 * @async
 */
export async function generateCryptoKeys(bits = 2048, hash = "SHA-256") {
  return await generatePair("RSA-OAEP", bits, hash, ["encrypt", "decrypt"]);
}

/**
 * @name generateSignKeys
 * @desc Generates a pair of keys to sign/verify data.
 * @param {number} bits
 * @param {string} hash SHA-256 or SHA-512
 * @returns {Promise<CryptoKeyPair>}
 * @async
 */
export async function generateSignKeys(bits = 2048, hash = "SHA-256") {
  return await generatePair("RSASSA-PKCS1-v1_5", bits, hash, [
    "sign",
    "verify"
  ]);
}

/**
 * @name toPem
 * @desc Converts a keyPair to PEM strings.
 * @param {CryptoKeyPair} keyPair
 * @returns {Promise<{privateKey:string,publicKey:string}>}
 * @async
 */
export async function toPem(keyPair) {
  const privateKey = await subtle.exportKey("pkcs8", keyPair.privateKey);
  const publicKey = await subtle.exportKey("pkcs8", keyPair.publicKey);
  return {
    privateKey: toPemString(privateKey, "PRIVATE"),
    publicKey: toPemString(publicKey, "PUBLIC")
  };
}

/**
 * @name sign
 * @desc Signs data with key using algorithm.
 * @param {CryptoKeyPair} key
 * @param {Uint8Array} data
 * @param {string} algorythm
 * @returns {Signature}
 * @async
 */
export async function sign(key, data, algorythm = "RSASSA-PKCS1-v1_5") {
  const sig = await subtle.sign({ name: algorythm }, key, data);
  return new Signature(sig, 1, sig.length);
}

/**
 * @class Signature
 * @desc Signature object
 * @extends Uint8Array
 */
export class Signature extends Uint8Array {
  /**
   * @name toString
   * @desc Returns signature as string.
   * @returns {string}
   */
  toString() {
    return btoa(ab2str(this));
  }

  /**
   * @name toJSON
   * @desc Returns signature to encode to json.
   * @returns {string}
   */
  toJSON() {
    return this.toString();
  }

  /**
   * @name from
   * @desc Creates a new Signature object from string.
   * @param {string} str
   * @returns {string}
   */
  static from(str) {
    return new Signature(str2ab(atob(str)));
  }
}

async function generatePair(name, bits, hash, opts) {
  return await subtle.generateKey(
    {
      name,
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: hash }
    },
    true,
    opts
  );
}

function arrayBufferToBase64(arrayBuffer) {
  const byteArray = new Uint8Array(arrayBuffer);
  let byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}

function addNewLines(str) {
  let finalString = "";
  while (str.length > 0) {
    finalString += str.substring(0, 64) + "\n";
    str = str.substring(64);
  }
  return finalString;
}

function toPemString(privateKey, type) {
  return `-----BEGIN ${type} KEY-----\n${addNewLines(
    arrayBufferToBase64(privateKey)
  )}-----END ${type} KEY-----`;
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, buf);
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  let bufView = new Uint8Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
