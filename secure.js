// The phone's side of the secure channel: the handshake, and sealed messages.
// The twin of the CLIENT role of src/phonedeck/core/secure_channel.py (read that module's text
// for the protocol). This file has no Bluetooth in it, so it is tested with node, against the
// bytes that the Python code makes.
//
// The handshake, four HANDSHAKE messages (request id 0, body = step byte + data):
//   1. CLIENT_HELLO    phone -> computer   the phone's nonce
//   2. SERVER_HELLO    computer -> phone   the computer's nonce
//   3. CLIENT_CONFIRM  phone -> computer   sealed (counter 0, empty): proves the phone has the key
//   4. SERVER_CONFIRM  computer -> phone   sealed (counter 0, empty): proves the computer has it
// After that every message is sealed. Counters start at 1 and go up.

import {
  CryptoError,
  NONCE_SIZE,
  SEAL_OVERHEAD,
  deriveSessionKeys,
  openSealed,
  seal,
} from "./crypto.js";
import { Kind, MAX_BODY_SIZE, ProtocolError, decodeMessage, encodeMessage } from "./protocol.js";

export const HandshakeStep = Object.freeze({
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CLIENT_CONFIRM: 3,
  SERVER_CONFIRM: 4,
});

/** Thrown when a message cannot be trusted, the handshake fails, or the session is misused. */
export class SecureChannelError extends Error {}

/** The additional authenticated data of a message: the kind (1 byte), the request id (2 bytes). */
function aadFor(kind, requestId) {
  return Uint8Array.of(kind, (requestId >> 8) & 0xff, requestId & 0xff);
}

function withStep(step, data) {
  const body = new Uint8Array(1 + data.length);
  body[0] = step;
  body.set(data, 1);
  return body;
}

export class ClientSession {
  #pairingKey;
  #random;
  #clientNonce = null;
  #keys = null;
  #ready = false;
  #sendCounter = 1; // 0 was used by CLIENT_CONFIRM
  #lastReceivedCounter = 0;

  /**
   * @param {Uint8Array} pairingKey the key from the QR code
   * @param {(size: number) => Uint8Array} random only replaced by the tests
   */
  constructor(pairingKey, random = (size) => crypto.getRandomValues(new Uint8Array(size))) {
    this.#pairingKey = pairingKey;
    this.#random = random;
  }

  /** True when the handshake is done and messages can be sent and received. */
  get ready() {
    return this.#ready;
  }

  /** Step 1: the packet to send first. */
  hello() {
    this.#clientNonce = this.#random(NONCE_SIZE);
    return encodeMessage(Kind.HANDSHAKE, 0, withStep(HandshakeStep.CLIENT_HELLO, this.#clientNonce));
  }

  /** Step 2 in, step 3 out: read the computer's hello, and answer with the confirm packet. */
  async handleServerHello(packet) {
    if (this.#clientNonce === null) throw new SecureChannelError("Send hello() first");
    const serverNonce = this.#handshakeData(packet, HandshakeStep.SERVER_HELLO);
    if (serverNonce.length !== NONCE_SIZE) {
      throw new SecureChannelError(`Server nonce must be ${NONCE_SIZE} bytes`);
    }
    this.#keys = await deriveSessionKeys(this.#pairingKey, this.#clientNonce, serverNonce);
    const confirm = await seal(
      this.#keys.clientToServer,
      0,
      aadFor(Kind.HANDSHAKE, 0),
      new Uint8Array(),
    );
    return encodeMessage(Kind.HANDSHAKE, 0, withStep(HandshakeStep.CLIENT_CONFIRM, confirm));
  }

  /** Step 4 in: check the computer's confirm. After this, ready is true. */
  async handleServerConfirm(packet) {
    if (this.#keys === null) throw new SecureChannelError("Read the server hello first");
    const sealed = this.#handshakeData(packet, HandshakeStep.SERVER_CONFIRM);
    let opened;
    try {
      opened = await openSealed(this.#keys.serverToClient, aadFor(Kind.HANDSHAKE, 0), sealed);
    } catch (error) {
      if (!(error instanceof CryptoError)) throw error;
      throw new SecureChannelError("The computer could not prove it has the pairing key");
    }
    if (opened.counter !== 0 || opened.plaintext.length !== 0) {
      throw new SecureChannelError("The computer's confirm has the wrong counter or content");
    }
    this.#ready = true;
  }

  /**
   * Seal a message for the computer.
   * @returns {Promise<Uint8Array>} the packet to send
   */
  async seal(kind, requestId, body) {
    if (!this.#ready) throw new SecureChannelError("The handshake is not done");
    if (kind === Kind.HANDSHAKE) throw new SecureChannelError("Not a data message kind");
    if (body.length > MAX_BODY_SIZE - SEAL_OVERHEAD) {
      throw new SecureChannelError(`Body too long: ${body.length} bytes`);
    }
    // Take the counter BEFORE the await, so that two calls at once can never share a counter.
    const counter = this.#sendCounter;
    this.#sendCounter += 1;
    const sealed = await seal(this.#keys.clientToServer, counter, aadFor(kind, requestId), body);
    return encodeMessage(kind, requestId, sealed);
  }

  /**
   * Read a packet from the computer. Anything that cannot be trusted (it does not open, it is a
   * replay, it is a handshake message) throws SecureChannelError. The caller must then hang up.
   * @returns {Promise<{kind: number, requestId: number, body: Uint8Array}>}
   */
  async open(packet) {
    if (!this.#ready) throw new SecureChannelError("The handshake is not done");
    const message = decodeMessage(packet); // a ProtocolError for garbage passes through
    if (message.kind === Kind.HANDSHAKE) {
      throw new SecureChannelError("A handshake message after the handshake");
    }
    let opened;
    try {
      opened = await openSealed(
        this.#keys.serverToClient,
        aadFor(message.kind, message.requestId),
        message.body,
      );
    } catch (error) {
      if (!(error instanceof CryptoError)) throw error;
      throw new SecureChannelError("A message failed its authentication check");
    }
    if (opened.counter <= this.#lastReceivedCounter) {
      throw new SecureChannelError(`Replay: counter ${opened.counter} is not new`);
    }
    this.#lastReceivedCounter = opened.counter;
    return { kind: message.kind, requestId: message.requestId, body: opened.plaintext };
  }

  /** The data of a HANDSHAKE packet of the expected step. */
  #handshakeData(packet, step) {
    let message;
    try {
      message = decodeMessage(packet);
    } catch (error) {
      if (!(error instanceof ProtocolError)) throw error;
      throw new SecureChannelError(`Garbage during the handshake: ${error.message}`);
    }
    if (message.kind !== Kind.HANDSHAKE || message.body.length === 0 || message.body[0] !== step) {
      throw new SecureChannelError(`Expected handshake step ${step}`);
    }
    return message.body.slice(1);
  }
}
