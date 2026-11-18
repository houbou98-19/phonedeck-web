// The page: pair with the QR code, show CPU and RAM as speedometers, and buttons that command the
// computer.

import { PhoneDeckLink } from "./ble.js";
import { Kind, ProtocolError, Status, parsePairingFragment } from "./protocol.js";

const $ = (id) => document.getElementById(id);
const link = new PhoneDeckLink();
let refreshTimer = null;

/** Write to the log, which is kept under "Details" for whoever wants it. */
function log(text) {
  const time = new Date().toLocaleTimeString();
  $("log").textContent = `${time}  ${text}\n` + $("log").textContent;
}

/** Tell the user something in plain view, and keep it in the log too. */
function say(text) {
  $("message").textContent = text;
  log(text);
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

/** Green below 60 %, amber up to 85 %, red above. */
function levelOf(percent) {
  if (percent >= 85) return "high";
  if (percent >= 60) return "warn";
  return "ok";
}

/** Draw a percentage in a speedometer: the arc is filled that far, and the needle points there. */
function showDial(name, percent) {
  const gauge = $(name);
  gauge.dataset.level = levelOf(percent);
  gauge.querySelector(".gauge-value").textContent = `${percent} %`;
  gauge.querySelector(".fill").style.strokeDashoffset = String(100 - percent);
  // The needle points left at 0 % and right at 100 %: a half turn from -90 to +90 degrees.
  gauge.querySelector(".needle").style.transform = `rotate(${percent * 1.8 - 90}deg)`;
}

/** Ask the computer for a percentage and show it in a gauge. */
async function refresh(name) {
  const { status, data } = await link.request(Kind.QUERY, name);
  if (status !== Status.OK) throw new Error(`${name}: status ${status}`);
  showDial(name, data[0]);
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
    say("There is no pairing code. Scan the QR code on the computer.");
    return;
  }
  try {
    say("Choose the computer in the list...");
    await link.connect(pairing.serviceUuid, pairing.key);
    // The key is used up. Take it out of the address bar, and out of the page.
    history.replaceState(null, "", location.pathname + location.search);
    $("link").value = "";
    setConnected(true);
    $("message").textContent = "";
    log("Paired. The link is encrypted.");
    startRefreshing();
  } catch (error) {
    log(`Could not connect: ${error.message}`);
    say("Could not connect. A code lasts a short while and works once: scan the new one.");
  }
});

$("disconnect").addEventListener("click", () => link.disconnect());

// Every command button works the same way: send its data-action, report the result.
for (const tile of document.querySelectorAll(".tile[data-action]")) {
  tile.addEventListener("click", async () => {
    const action = tile.dataset.action;
    try {
      const { status } = await link.request(Kind.COMMAND, action);
      say(status === Status.OK ? `${tile.dataset.label}.` : `"${action}" failed (status ${status}).`);
    } catch (error) {
      say(`"${action}" failed: ${error.message}`);
    }
  });
}

link.onDisconnect = () => {
  stopRefreshing();
  setConnected(false);
  showHint();
  say("Disconnected.");
};

if (!("bluetooth" in navigator)) {
  say("This browser has no Web Bluetooth. Use Chrome on Android.");
  $("connect").disabled = true;
}
setConnected(false);
showHint();
