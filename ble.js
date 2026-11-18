// Web Bluetooth: the phone's side of the BLE link to the computer.
//
// The computer is the peripheral. This page is the central: it finds the computer by its
// service UUID, pairs with the key from the QR code (the handshake in secure.js), and then sends
// sealed requests to the write characteristic and reads sealed responses from the notify
// characteristic. A request and its response are matched by the request id.
//
// This file needs a real phone and a real computer, so it has no tests. The parts with logic in
// them (the handshake and the sealing) are in secure.js, and they are tested.

import {
  Kind,
  MAX_REQUEST_ID,
  ProtocolError,
  characteristicUuids,
  parseResponseBody,
} from "./protocol.js";
import { ClientSession, SecureChannelError } from "./secure.js";

const REQUEST_TIMEOUT_MS = 5000;
const HANDSHAKE_STEP_TIMEOUT_MS = 5000;

export class PhoneDeckLink {
  #device = null;
  #write = null;
  #session = null;
  #pending = new Map(); // request id -> { resolve, reject, timer }
  #nextRequestId = 1;

  // During the handshake the packets from the computer are read one at a time.
  #inbox = []; // packets that have arrived and not been read yet
  #inboxWaiter = null; // { resolve, timer } while the handshake waits for a packet

  // Things must happen one at a time and in order: the counters have to go up on the wire.
  #sendChain = Promise.resolve();
  #receiveChain = Promise.resolve();

  /** Called when the link goes down (the computer went away, or disconnect() was called). */
  onDisconnect = () => {};

  get connected() {
    return this.#device?.gatt?.connected === true && this.#session?.ready === true;
  }

  /**
   * Let the user pick the computer in Chrome's chooser, connect, and pair with the key.
   * Must be called from a click, because Web Bluetooth requires a user gesture.
   *
   * @param {string} serviceUuid from the QR code
   * @param {Uint8Array} pairingKey from the QR code (16 bytes)
   * @throws {SecureChannelError} if the computer does not accept the key (it has expired, or it
   *   was a different key). The link is then closed.
   */
  async connect(serviceUuid, pairingKey) {
    const { write, notify } = await characteristicUuids(serviceUuid);

    this.#device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [serviceUuid] }],
    });
    this.#device.addEventListener("gattserverdisconnected", () => this.#handleDisconnect());

    const server = await this.#device.gatt.connect();
    const service = await server.getPrimaryService(serviceUuid);
    this.#write = await service.getCharacteristic(write);
    const notifyCharacteristic = await service.getCharacteristic(notify);

    this.#session = new ClientSession(pairingKey);
    this.#inbox = [];
    notifyCharacteristic.addEventListener("characteristicvaluechanged", (event) =>
      this.#handleNotification(event.target.value),
    );
    await notifyCharacteristic.startNotifications();

    try {
      await this.#handshake();
    } catch (error) {
      this.disconnect();
      throw error;
    }
  }

  /**
   * Send a request and wait for its response.
   * @param {number} kind Kind.COMMAND or Kind.QUERY
   * @param {string} name the action, for example "lock" or "cpu"
   * @returns {Promise<{status: number, data: Uint8Array}>}
   */
  async request(kind, name) {
    if (!this.connected) throw new Error("Not connected");

    const requestId = this.#nextRequestId;
    this.#nextRequestId = (requestId % MAX_REQUEST_ID) + 1; // 1, 2, ... 65535, 1, ...

    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(requestId);
        reject(new Error(`No answer to "${name}" within ${REQUEST_TIMEOUT_MS / 1000} s`));
      }, REQUEST_TIMEOUT_MS);
      this.#pending.set(requestId, { resolve, reject, timer });
    });

    // Sealing and writing happen as one step, in the order of the calls: the counter goes up
    // with every message, and the computer refuses a counter that is not larger than the last.
    const sent = this.#sendChain.then(async () => {
      const packet = await this.#session.seal(kind, requestId, new TextEncoder().encode(name));
      await this.#write.writeValueWithResponse(packet);
    });
    this.#sendChain = sent.catch(() => {});
    try {
      await sent;
    } catch (error) {
      this.#settle(requestId, (pending) => pending.reject(error));
      throw error;
    }
    return response;
  }

  disconnect() {
    if (this.#device?.gatt?.connected) this.#device.gatt.disconnect();
  }

  // --- the handshake ---

  async #handshake() {
    await this.#write.writeValueWithResponse(this.#session.hello());
    const serverHello = await this.#nextHandshakePacket();
    await this.#write.writeValueWithResponse(await this.#session.handleServerHello(serverHello));
    const serverConfirm = await this.#nextHandshakePacket();
    await this.#session.handleServerConfirm(serverConfirm);
  }

  #nextHandshakePacket() {
    if (this.#inbox.length > 0) return Promise.resolve(this.#inbox.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#inboxWaiter = null;
        reject(new SecureChannelError("The computer did not answer. Is the code still valid?"));
      }, HANDSHAKE_STEP_TIMEOUT_MS);
      this.#inboxWaiter = { resolve, timer };
    });
  }

  // --- what comes from the computer ---

  #handleNotification(view) {
    if (this.#session === null) return; // the link has been closed and forgotten
    // The DataView from Web Bluetooth may be a window into a bigger buffer, so take a copy.
    const packet = new Uint8Array(view.buffer, view.byteOffset, view.byteLength).slice();

    if (!this.#session.ready) {
      if (this.#inboxWaiter) {
        const { resolve, timer } = this.#inboxWaiter;
        this.#inboxWaiter = null;
        clearTimeout(timer);
        resolve(packet);
      } else {
        this.#inbox.push(packet);
      }
      return;
    }
    // Opening is asynchronous, but the order matters (the replay check), so one at a time.
    this.#receiveChain = this.#receiveChain.then(() => this.#handleData(packet));
  }

  async #handleData(packet) {
    if (this.#session === null) return; // the link was closed while this was waiting its turn
    try {
      const message = await this.#session.open(packet);
      if (message.kind !== Kind.RESPONSE) return;
      const response = parseResponseBody(message.body);
      this.#settle(message.requestId, (pending) => pending.resolve(response));
    } catch (error) {
      if (error instanceof SecureChannelError) {
        // Something that cannot be trusted: hang up, like the computer does.
        console.warn("Hanging up, a message could not be trusted:", error.message);
        this.disconnect();
      } else if (error instanceof ProtocolError) {
        console.warn("Ignoring a bad packet from the computer:", error.message);
      } else {
        throw error;
      }
    }
  }

  #settle(requestId, action) {
    const pending = this.#pending.get(requestId);
    if (!pending) return; // a late answer to a request that already timed out
    clearTimeout(pending.timer);
    this.#pending.delete(requestId);
    action(pending);
  }

  #handleDisconnect() {
    if (this.#inboxWaiter) clearTimeout(this.#inboxWaiter.timer);
    this.#inboxWaiter = null;
    for (const requestId of [...this.#pending.keys()]) {
      this.#settle(requestId, (pending) => pending.reject(new Error("Disconnected")));
    }
    this.onDisconnect();
    this.#forgetComputer();
  }

  /**
   * Make the browser forget the computer, so that the next time needs a new scan of the QR code
   * and a new choice in the list. (The pairing key is already used up and cannot work again, but
   * the browser would otherwise keep its permission to use this device.)
   */
  #forgetComputer() {
    const device = this.#device;
    this.#device = null;
    this.#session = null;
    // forget() is in Chrome 101 and later. In an older one there is nothing to forget.
    device?.forget?.().catch(() => {});
  }
}
