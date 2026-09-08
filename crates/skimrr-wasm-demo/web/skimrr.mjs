/* The whole of the JavaScript side.
 *
 * There is deliberately very little of it. Every decision about what a `.skimrr` is —
 * the framing, the key derivation, the authentication, what counts as a safe path —
 * lives in the WebAssembly module, which is the same code the desktop application runs.
 * This file moves bytes across the boundary and does nothing else, because anything it
 * decided for itself would be a second implementation of the format.
 *
 * Nothing here touches the network. There is no fetch of user data, no upload, no
 * telemetry; the only fetch is the module itself.
 */

const RESULT_HEADER = 4; // a u32 little-endian length prefix

export async function loadSkimrr(wasm) {
  let memory;

  /* The module's one and only import. WebAssembly has no random number generator of its
   * own, so the host lends it the platform's — the same one the operating system gives
   * the desktop build. */
  const imports = {
    env: {
      skimrr_random(ptr, len) {
        try {
          const bytes = new Uint8Array(memory.buffer, ptr, len);
          // `getRandomValues` refuses more than 65536 bytes at a time.
          for (let at = 0; at < len; at += 65536) {
            crypto.getRandomValues(bytes.subarray(at, Math.min(at + 65536, len)));
          }
          return 0;
        } catch {
          // Reported rather than substituted: the module treats this as a hard failure,
          // which is the only safe thing to do when randomness is unavailable.
          return 1;
        }
      },
    },
  };

  const source = wasm instanceof Response ? wasm : await Promise.resolve(wasm);
  const { instance } =
    source instanceof Response
      ? await WebAssembly.instantiateStreaming(source, imports)
      : await WebAssembly.instantiate(source, imports);

  const wasmExports = instance.exports;
  memory = wasmExports.memory;

  /** Copies bytes in, runs `body(ptr, len)`, and always gives the memory back. */
  function withBytes(bytes, body) {
    const ptr = wasmExports.sk_alloc(bytes.length);
    try {
      new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
      return body(ptr, bytes.length);
    } finally {
      wasmExports.sk_dealloc(ptr, bytes.length);
    }
  }

  /* The password is copied into the module, used, and the buffer is overwritten with
   * zeroes before it is released — so a later allocation cannot come back holding it.
   * The module wipes its own derived key the same way. */
  function withPassword(password, body) {
    if (!password) return body(0, 0);
    const bytes = new TextEncoder().encode(password);
    const ptr = wasmExports.sk_alloc(bytes.length);
    try {
      new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
      return body(ptr, bytes.length);
    } finally {
      new Uint8Array(memory.buffer, ptr, bytes.length).fill(0);
      bytes.fill(0);
      wasmExports.sk_dealloc(ptr, bytes.length);
    }
  }

  function takeBytes(ptr) {
    const length = new DataView(memory.buffer).getUint32(ptr, true);
    const copy = new Uint8Array(memory.buffer, ptr + RESULT_HEADER, length).slice();
    wasmExports.sk_free(ptr);
    return copy;
  }

  const takeJson = (ptr) => JSON.parse(new TextDecoder().decode(takeBytes(ptr)));

  return {
    /** What the file says about itself. No password, no decryption. */
    peek: (file) => withBytes(file, (ptr, len) => takeJson(wasmExports.sk_peek(ptr, len))),

    /** Opens it. Returns `{ ok: false, error }` rather than throwing. */
    open: (file, password) =>
      withBytes(file, (ptr, len) =>
        withPassword(password, (pw, pwLen) =>
          takeJson(wasmExports.sk_open(ptr, len, pw, pwLen)),
        ),
      ),

    /** One thumbnail from the container already open, as raw bytes. Empty if there is
        no such blob. Costs a copy, not a key derivation. */
    blob: (index) => takeBytes(wasmExports.sk_blob(index)),

    /** Drops the open container and the decrypted project inside it. */
    forget: () => wasmExports.sk_forget(),

    /** Milliseconds for one key derivation at the given cost, measured here. */
    benchArgon2(mKib, t, p) {
      const started = performance.now();
      wasmExports.sk_bench_argon2(mKib, t, p);
      return performance.now() - started;
    },
  };
}
