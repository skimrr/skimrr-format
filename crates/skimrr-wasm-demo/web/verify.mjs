/* Runs the browser path without a browser.
 *
 * Node's WebAssembly is the same engine Chrome uses, so this exercises the real module
 * through the real glue — and being runnable from a terminal means it can be a test
 * rather than something somebody has to remember to click.
 *
 * Usage: node web/verify.mjs <sample.skimrr> <encrypted.skimrr> <password>
 */
import { readFileSync } from "node:fs";
import { loadSkimrr } from "./skimrr.mjs";

const [plainPath, encryptedPath, password] = process.argv.slice(2);
const wasm = readFileSync(
  new URL("../target/wasm32-unknown-unknown/release/skimrr_wasm_demo.wasm", import.meta.url),
);

let failures = 0;
function check(what, condition, detail = "") {
  const mark = condition ? "  ok " : "FAIL ";
  if (!condition) failures++;
  console.log(`${mark} ${what}${detail ? ` — ${detail}` : ""}`);
}

const skimrr = await loadSkimrr(wasm);

// ---- a plain container
const plain = readFileSync(plainPath);
const plainHead = skimrr.peek(plain);
check("peek reads a plain container", plainHead.ok && !plainHead.encrypted);
const opened = skimrr.open(plain, null);
check("open returns the project", opened.ok, opened.ok ? `“${opened.name}”, ${opened.photos} photos` : opened.error);
check("entries came across", opened.entries.length === opened.photos);
check("paths are relative", opened.entries.every((e) => !e.path.startsWith("/")));
check("groups came across", opened.groups.length === 1 && opened.groups[0].members.length === 3);
const thumb = skimrr.blob(0);
check("a thumbnail can be read back", thumb.length === 4096, `${thumb.length} bytes`);

// ---- an encrypted one
const encrypted = readFileSync(encryptedPath);
const head = skimrr.peek(encrypted);
check("peek reports encryption without a key", head.ok && head.encrypted, head.kdf && `Argon2id ${head.kdf.m_kib / 1024} MiB, t=${head.kdf.t}`);
const wrong = skimrr.open(encrypted, "not the password");
check("a wrong password is refused", !wrong.ok, wrong.error);
const none = skimrr.open(encrypted, null);
check("no password is refused", !none.ok, none.error);
const right = skimrr.open(encrypted, password);
check("the right password opens it", right.ok, right.ok ? `${right.photos} photos` : right.error);
check("both containers agree", right.ok && right.name === opened.name);

// ---- and the tampering the desktop tests cover, proven again here
const flipped = Uint8Array.from(encrypted);
flipped[flipped.length - 40] ^= 1;
check("a flipped bit in the body is caught", !skimrr.open(flipped, password).ok);

const headerEdit = Uint8Array.from(encrypted);
headerEdit[20] ^= 1;
check("a flipped bit in the header is caught", !skimrr.open(headerEdit, password).ok);

const truncated = encrypted.subarray(0, encrypted.length - 1);
check("a truncated file is caught", !skimrr.open(truncated, password).ok);

const appended = new Uint8Array(encrypted.length + 8);
appended.set(encrypted);
check("trailing bytes are caught", !skimrr.open(appended, password).ok);

check("rubbish is not mistaken for a project", !skimrr.open(new Uint8Array([1, 2, 3]), null).ok);
check("an empty file is not mistaken for a project", !skimrr.open(new Uint8Array(0), null).ok);

// ---- the cost of the key derivation, on this engine
for (const [m, t, label] of [[19456, 2, "OWASP minimum"], [131072, 3, "Strong"], [262144, 4, "Maximum"]]) {
  console.log(`     ${label.padEnd(15)} ${(m / 1024).toString().padStart(4)} MiB t=${t}  ${skimrr.benchArgon2(m, t, 1).toFixed(0)} ms`);
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
