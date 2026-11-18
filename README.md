# PhoneDeck: the phone page

The phone side of **PhoneDeck**, a way to use your phone as a wireless control panel for your
computer over Bluetooth Low Energy (BLE): live CPU and RAM, and a button that locks the computer.

You do not open this page yourself. PhoneDeck, running on your computer, shows a **QR code**.
Scanning it with the phone's camera opens this page with a one-time pairing key in the address.
The key sits after the `#`, which a browser never sends to any server, so it never reaches this
site. The page then connects to the computer with Web Bluetooth, pairs with the key, and from
then on everything is encrypted (AES-GCM, with keys derived from the pairing key).

- Needs **Chrome on Android** (Web Bluetooth).
- This site is static: no server code, no tracking, no data collected.
- The pairing key works once, and only for a short time (60 seconds by default).
- The computer side (Windows, Python) is not published yet.

## The files

| File | What it does |
|---|---|
| `index.html` | The page: gauges, the lock button, the log |
| `app.js` | Connects the page to the buttons and gauges |
| `ble.js` | The Web Bluetooth link: connect, send requests, match responses |
| `secure.js` | The phone's side of the handshake, and sealing and opening messages |
| `crypto.js` | HKDF and AES-GCM with the browser's WebCrypto |
| `protocol.js` | Frames, messages and the pairing link |

## License

MIT, see `LICENSE`.
