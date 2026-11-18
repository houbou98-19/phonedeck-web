// The page: pair with the QR code, show CPU and RAM, and a button that locks the computer.

import { PhoneDeckLink } from "./ble.js";
import { Kind, ProtocolError, Status, parsePairingFragment } from "./protocol.js";

const $ = (id) => document.getElementById(id);
const link = new PhoneDeckLink();
let refreshTimer = null;

function log(text) {
  const time = new Date().toLocaleTimeString();
  $("log").textContent = `${time}  ${text}\n` + $("log").textContent;
}

/**
 * The pairing link: the address in the QR code has the service UUID and the one-time key after
 * the # (the browser never sends that part to a server). It can also be pasted.
 */
function readPairing() {
  const pasted = $("link").value.trim();
  const source = pasted || location.hash;
  const hash = source.indexOf("#");
  return parsePairingFragment(hash === -1 ? source : source.slice(hash + 1));
}

function setConnected(connected) {
  $("status").textContent = connected ? "Connected and paired" : "Not connected";
  $("status").dataset.state = connected ? "on" : "off";
  $("connect").hidden = connected;
  $("service-row").hidden = connected;
  $("deck").hidden = !connected;
  $("disconnect").hidden = !connected;
}

function showHint() {
  const hasLink = location.hash.length > 1;
  $("hint").textContent = hasLink
    ? "The pairing code is in the address. Tap Connect, and choose the computer in the list."
    : "Scan the QR code on the computer with the phone's camera. It opens this page.";
  $("link-label").hidden = hasLink;
  $("link").hidden = hasLink;
}

/** Ask the computer for a percentage and show it in a gauge. */
async function refresh(name) {
  const { status, data } = await link.request(Kind.QUERY, name);
  if (status !== Status.OK) throw new Error(`${name}: status ${status}`);
  const percent = data[0];
  $(`${name}-value`).textContent = `${percent} %`;
  $(`${name}-bar`).value = percent;
}

async function refreshAll() {
  try {
    await refresh("cpu");
    await refresh("ram");
  } catch (error) {
    log(`Could not read: ${error.message}`);
  }
}

function startRefreshing() {
  refreshAll();
  refreshTimer = setInterval(refreshAll, 2000);
}

function stopRefreshing() {
  clearInterval(refreshTimer);
  refreshTimer = null;
}

$("connect").addEventListener("click", async () => {
  let pairing;
  try {
    pairing = readPairing();
  } catch (error) {
    if (!(error instanceof ProtocolError)) throw error;
    log("There is no pairing code. Scan the QR code on the computer.");
    return;
  }
  try {
    log("Choose the computer in the list...");
    await link.connect(pairing.serviceUuid, pairing.key);
    // The key is used up. Take it out of the address bar, and out of the page.
    history.replaceState(null, "", location.pathname + location.search);
    $("link").value = "";
    setConnected(true);
    log("Paired. The link is encrypted.");
    startRefreshing();
  } catch (error) {
    log(`Could not connect: ${error.message}`);
    log("The code only lasts 60 seconds, and can be used once. Scan the new code on the computer.");
  }
});

$("disconnect").addEventListener("click", () => link.disconnect());

$("lock").addEventListener("click", async () => {
  try {
    const { status } = await link.request(Kind.COMMAND, "lock");
    log(status === Status.OK ? "The computer is locked." : `Lock failed (status ${status}).`);
  } catch (error) {
    log(`Lock failed: ${error.message}`);
  }
});

link.onDisconnect = () => {
  stopRefreshing();
  setConnected(false);
  showHint();
  log("Disconnected.");
};

if (!("bluetooth" in navigator)) {
  log("This browser has no Web Bluetooth. Use Chrome on Android.");
  $("connect").disabled = true;
}
setConnected(false);
showHint();
