// The cryptographic building blocks of the handshake, with the browser's WebCrypto.
// The twin of src/phonedeck/security/crypto.py: the same key derivation, the same sealing, and
// the tests use the same known values. Nothing is invented here: HKDF and AES-GCM are called, and
// that is all.
//
// How the pieces fit together (the design is in docs/decisions.md):
//   * The computer shows a pairing key in a QR code. The phone scans it. It never travels over
//     Bluetooth.
//   * Each side makes a random nonce and sends it in the clear.
//   * Both run deriveSessionKeys(pairingKey, clientNonce, serverNonce) and get the same two keys,
//     one for each direction.
//   * Every later message is sealed with AES-GCM. The message kind and request id are not hidden,
//     but they are "additional authenticated data": if anyone changes them, opening fails.

export const PAIRING_KEY_SIZE = 16; // bytes: 128 random bits
export const NONCE_SIZE = 16; // bytes
export const KEY_SIZE = 32; // bytes: AES-256
export const COUNTER_SIZE = 8; // bytes: sent in the clear in front of every sealed message
export const TAG_SIZE = 16; // bytes: the AES-GCM authentication tag
export const SEAL_OVERHEAD = COUNTER_SIZE + TAG_SIZE;

// Python allows counters up to 2**64 - 1. JavaScript numbers are exact only up to 2**53 - 1,
// which is far more messages than a session will ever have.
export const MAX_COUNTER = Number.MAX_SAFE_INTEGER;

const HKDF_INFO = new TextEncoder().encode("phonedeck v1 session");

/** Thrown for a bad key, a bad size, or a message that fails its authentication check. */
export class CryptoError extends Error {}

function concat(a, b) {
  const joined = new Uint8Array(a.length + b.length);
  joined.set(a, 0);
  joined.set(b, a.length);
  return joined;
}

/** The AES-GCM nonce: the counter as 12 bytes, big-endian (like Python's counter.to_bytes(12)). */
function nonceFor(counter) {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(counter));
  return nonce;
}

/** A fresh random nonce, NONCE_SIZE bytes. */
export function newNonce() {
  return crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
}

/**
 * Turn the pairing key and the two nonces into the two session keys.
 *
 * HKDF with SHA-256. The secret is the pairing key, the salt is clientNonce followed by
 * serverNonce, the info is "phonedeck v1 session", and the output is 64 bytes: the first 32 are
 * clientToServer, the last 32 are serverToClient.
 *
 * @param {Uint8Array} pairingKey PAIRING_KEY_SIZE bytes
 * @param {Uint8Array} clientNonce NONCE_SIZE bytes
 * @param {Uint8Array} serverNonce NONCE_SIZE bytes
 * @returns {Promise<{clientToServer: CryptoKey, serverToClient: CryptoKey}>} AES-GCM keys
 * @throws {CryptoError} for a wrong size
 */
export async function deriveSessionKeys(pairingKey, clientNonce, serverNonce) {
  if (pairingKey.length !== PAIRING_KEY_SIZE) {
    throw new CryptoError(`Pairing key must be ${PAIRING_KEY_SIZE} bytes, got ${pairingKey.length}`);
  }
  for (const [name, nonce] of [
    ["Client", clientNonce],
    ["Server", serverNonce],
  ]) {
    if (nonce.length !== NONCE_SIZE) {
      throw new CryptoError(`${name} nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
    }
  }

  const secret = await crypto.subtle.importKey("raw", pairingKey, "HKDF", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: concat(clientNonce, serverNonce), info: HKDF_INFO },
      secret,
      8 * 2 * KEY_SIZE,
    ),
  );
  const asAesKey = (bytes) =>
    crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
  return {
    clientToServer: await asAesKey(bits.slice(0, KEY_SIZE)),
    serverToClient: await asAesKey(bits.slice(KEY_SIZE)),
  };
}

/**
 * Encrypt and authenticate one message.
 *
 * @param {CryptoKey} key a session key
 * @param {number} counter 0 up to MAX_COUNTER. The same key must never see the same counter twice.
 * @param {Uint8Array} aad additional authenticated data: not encrypted, but part of the check
 * @param {Uint8Array} plaintext
 * @returns {Promise<Uint8Array>} the counter (8 bytes, big-endian), then ciphertext and tag
 * @throws {CryptoError} if the counter is out of range
 */
export async function seal(key, counter, aad, plaintext) {
  if (!Number.isInteger(counter) || counter < 0 || counter > MAX_COUNTER) {
    throw new CryptoError(`Counter must be a whole number 0-${MAX_COUNTER}, got ${counter}`);
  }
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceFor(counter), additionalData: aad, tagLength: 8 * TAG_SIZE },
      key,
      plaintext,
    ),
  );
  const sealed = new Uint8Array(COUNTER_SIZE + encrypted.length);
  new DataView(sealed.buffer).setBigUint64(0, BigInt(counter));
  sealed.set(encrypted, COUNTER_SIZE);
  return sealed;
}

/**
 * Check and decrypt a message made by seal(). Whether the counter is new (not a replay) is for
 * the layer above to decide.
 *
 * @param {CryptoKey} key
 * @param {Uint8Array} aad
 * @param {Uint8Array} sealed
 * @returns {Promise<{counter: number, plaintext: Uint8Array}>}
 * @throws {CryptoError} if it is too short, or the authentication check fails (a changed byte,
 *   a changed counter, the wrong aad or the wrong key)
 */
export async function openSealed(key, aad, sealed) {
  if (sealed.length < SEAL_OVERHEAD) {
    throw new CryptoError(`A sealed message is at least ${SEAL_OVERHEAD} bytes, got ${sealed.length}`);
  }
  const view = new DataView(sealed.buffer, sealed.byteOffset, sealed.byteLength);
  const counterBig = view.getBigUint64(0);
  if (counterBig > BigInt(MAX_COUNTER)) throw new CryptoError("The counter is too large");
  const counter = Number(counterBig);
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceFor(counter), additionalData: aad, tagLength: 8 * TAG_SIZE },
        key,
        sealed.slice(COUNTER_SIZE),
      ),
    );
    return { counter, plaintext };
  } catch {
    throw new CryptoError("Authentication check failed");
  }
}
