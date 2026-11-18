// The PhoneDeck protocol in JavaScript: frames, messages and the derived UUIDs.
//
// This is the twin of the Python code (src/phonedeck/protocol/frame.py, message.py and
// src/phonedeck/transport/ble.py). Both sides must agree on every byte, so the tests in
// test/protocol.test.js use the same known values as the Python tests.
//
// Layout of one packet (all numbers are big-endian):
//
//   | version (1) | kind (1) | length (2) | request_id (2) | body (the rest) |
//   |<-------- frame header (4) -------->|<-------- payload (length bytes) -->|
//
// "length" counts the payload: the 2 bytes of request_id plus the body.

export const PROTOCOL_VERSION = 1;
export const HEADER_SIZE = 4;
export const MAX_PAYLOAD_SIZE = 508;
export const REQUEST_ID_SIZE = 2;
export const MAX_REQUEST_ID = 0xffff;
export const MAX_BODY_SIZE = MAX_PAYLOAD_SIZE - REQUEST_ID_SIZE; // 506

// What a message means. The numbers are part of the protocol.
export const Kind = Object.freeze({ COMMAND: 1, QUERY: 2, RESPONSE: 3, HANDSHAKE: 4 });

// The first byte of a RESPONSE body. The numbers are part of the protocol.
export const Status = Object.freeze({ OK: 0, UNKNOWN_ACTION: 1, FAILED: 2 });

const KNOWN_KINDS = new Set(Object.values(Kind));

// Thrown for anything that is wrong with a packet or a message.
export class ProtocolError extends Error {}

// --- UUIDs ---

/** A UUID as text (with or without dashes) -> its 16 bytes. */
function uuidToBytes(uuid) {
  const hex = String(uuid).replace(/[{}-]/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new ProtocolError(`Not a UUID: "${uuid}"`);
  return Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16));
}

/** 16 bytes -> a UUID as lowercase text, in the groups 8-4-4-4-12. */
function bytesToUuid(bytes) {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)]
    .join("-");
}

/**
 * A name-based UUID, version 5 (RFC 4122), like Python's uuid.uuid5(namespace, name).
 *
 * @param {string} namespace a UUID as text, in any letter case
 * @param {string} name any text (it is encoded as UTF-8)
 * @returns {Promise<string>} the new UUID, lowercase
 * @throws {ProtocolError} if namespace is not a UUID
 */
export async function uuid5(namespace, name) {
  const namespaceBytes = uuidToBytes(namespace);
  const nameBytes = new TextEncoder().encode(name);

  const input = new Uint8Array(namespaceBytes.length + nameBytes.length);
  input.set(namespaceBytes, 0);
  input.set(nameBytes, namespaceBytes.length);

  // SHA-1 of (namespace bytes + name bytes); the first 16 bytes become the UUID.
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-1", input));
  const bytes = hash.slice(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // the RFC 4122 variant
  return bytesToUuid(bytes);
}

/**
 * The two characteristic UUIDs for a service (the same rule as in transport/ble.py):
 * the namespace is the service UUID, the names are "write" and "notify".
 *
 * @param {string} serviceUuid
 * @returns {Promise<{write: string, notify: string}>}
 * @throws {ProtocolError} if serviceUuid is not a UUID
 */
export async function characteristicUuids(serviceUuid) {
  return {
    write: await uuid5(serviceUuid, "write"),
    notify: await uuid5(serviceUuid, "notify"),
  };
}

// --- The pairing link ---

/**
 * Read the part after the # of the address in the QR code: a service UUID, a dot and the pairing
 * key (URL-safe base64, no padding). The twin of parse_pairing_fragment in core/pairing.py.
 *
 * @param {string} fragment for example "277cedef-a9df-4ddf-bfd3-ee550dd20035.AAECAwQFBgcICQoLDA0ODw"
 *   (a leading # is allowed)
 * @returns {{serviceUuid: string, key: Uint8Array}} the service UUID in lowercase
 * @throws {ProtocolError} if it is not a service UUID, a dot and a key of 16 bytes
 */
export function parsePairingFragment(fragment) {
  const text = String(fragment).replace(/^#/, "");
  const dot = text.indexOf(".");
  if (dot === -1) throw new ProtocolError("The link has no key");
  const serviceUuid = bytesToUuid(uuidToBytes(text.slice(0, dot)));

  const keyText = text.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]*$/.test(keyText) || keyText.length % 4 === 1) {
    throw new ProtocolError("The key in the link is not valid base64");
  }
  const base64 = keyText.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const key = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (key.length !== 16) {
    throw new ProtocolError(`The key must be 16 bytes, got ${key.length}`);
  }
  return { serviceUuid, key };
}

// --- Messages ---

/**
 * Build the bytes of one packet: a frame with a message inside.
 *
 * @param {number} kind one of the numbers in Kind
 * @param {number} requestId a whole number, 0 to 65535
 * @param {Uint8Array} body at most MAX_BODY_SIZE bytes
 * @returns {Uint8Array} header (4 bytes) + request id (2 bytes) + body
 * @throws {ProtocolError} for an unknown kind, a bad request id or a body that is too large
 */
export function encodeMessage(kind, requestId, body) {
  if (!KNOWN_KINDS.has(kind)) throw new ProtocolError(`Unknown kind: ${kind}`);
  if (!Number.isInteger(requestId) || requestId < 0 || requestId > MAX_REQUEST_ID) {
    throw new ProtocolError(`Request id must be a whole number 0-${MAX_REQUEST_ID}: ${requestId}`);
  }
  if (body.length > MAX_BODY_SIZE) {
    throw new ProtocolError(`Body too large: ${body.length} bytes, max is ${MAX_BODY_SIZE}`);
  }

  const packet = new Uint8Array(HEADER_SIZE + REQUEST_ID_SIZE + body.length);
  const view = new DataView(packet.buffer);
  view.setUint8(0, PROTOCOL_VERSION);
  view.setUint8(1, kind);
  view.setUint16(2, REQUEST_ID_SIZE + body.length); // big-endian is the default
  view.setUint16(4, requestId);
  packet.set(body, HEADER_SIZE + REQUEST_ID_SIZE);
  return packet;
}

/**
 * Read one packet. The opposite of encodeMessage.
 *
 * @param {Uint8Array} bytes exactly one packet
 * @returns {{kind: number, requestId: number, body: Uint8Array}}
 * @throws {ProtocolError} if the packet is invalid: too short, wrong version, a length that does
 *   not match the bytes (too few or too many), a payload that is too short to hold a request
 *   id, or an unknown kind.
 */
export function decodeMessage(bytes) {
  if (bytes.length < HEADER_SIZE) {
    throw new ProtocolError(`Packet too short: ${bytes.length} bytes`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const version = view.getUint8(0);
  if (version !== PROTOCOL_VERSION) throw new ProtocolError(`Unsupported version: ${version}`);

  const kind = view.getUint8(1);
  const length = view.getUint16(2);
  if (length > MAX_PAYLOAD_SIZE) throw new ProtocolError(`Payload too large: ${length} bytes`);
  if (bytes.length !== HEADER_SIZE + length) {
    throw new ProtocolError(`Length says ${length} but ${bytes.length - HEADER_SIZE} bytes came`);
  }
  if (!KNOWN_KINDS.has(kind)) throw new ProtocolError(`Unknown kind: ${kind}`);
  if (length < REQUEST_ID_SIZE) throw new ProtocolError("Payload too short for a request id");

  return {
    kind,
    requestId: view.getUint16(HEADER_SIZE),
    body: bytes.slice(HEADER_SIZE + REQUEST_ID_SIZE),
  };
}

/**
 * Split the body of a RESPONSE: the first byte is the status, the rest is the data.
 *
 * @param {Uint8Array} body
 * @returns {{status: number, data: Uint8Array}}
 * @throws {ProtocolError} if the body is empty
 */
export function parseResponseBody(body) {
  if (body.length === 0) throw new ProtocolError("A response needs at least a status byte");
  return { status: body[0], data: body.slice(1) };
}
