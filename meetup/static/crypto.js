/* Encryption helpers for Huddle Corp (WebCrypto). Everything here runs in the browser; the server only ever
   receives wrapped keys and ciphertext.

   - Each person has an ECDH P-256 key pair. The private half never leaves their browser.
   - Each "scope" (the whole workspace, or a private group) has a random 256-bit AES-GCM key per epoch.
   - To give a teammate a scope key we "wrap" it: AES-GCM with a secret derived from ECDH(my private, their public).
   - Content is sealed with the scope key. The additional data binds each ciphertext to its workspace, scope,
     type and parent, so the server can't move it somewhere else and have it still open. */
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ECDH_ALG = { name: 'ECDH', namedCurve: 'P-256' };
const pubOnly = j => ({ kty: j.kty, crv: j.crv, x: j.x, y: j.y });
const enc = new TextEncoder(), dec = new TextDecoder();

async function genKeys() {
  const kp = await crypto.subtle.generateKey(ECDH_ALG, true, ['deriveBits']);
  return { pub: pubOnly(await crypto.subtle.exportKey('jwk', kp.publicKey)), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) };
}
async function sharedSecret(privJwk, theirPubJwk) {
  const mine = await crypto.subtle.importKey('jwk', privJwk, ECDH_ALG, false, ['deriveBits']);
  const theirs = await crypto.subtle.importKey('jwk', pubOnly(theirPubJwk), ECDH_ALG, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, mine, 256));
}
const aesKey = (raw, usage) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, usage);

/* wrapped = "iv.ciphertext" (both base64) */
async function wrapKey(privJwk, theirPubJwk, rawScopeKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await aesKey(await sharedSecret(privJwk, theirPubJwk), ['encrypt']);
  return b64(iv) + '.' + b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, rawScopeKey));
}
async function unwrapKey(privJwk, granterPubJwk, wrapped) {
  const [iv, ct] = wrapped.split('.');
  const k = await aesKey(await sharedSecret(privJwk, granterPubJwk), ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, k, unb64(ct)));
}
async function sealJson(key, obj, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function openJson(key, iv, ct, aad) {
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv), additionalData: aad }, key, unb64(ct))));
}
/* a short code two people can read to each other to confirm they hold the same key */
async function fingerprint(pubJwk) {
  const h = [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(pubJwk.x + '.' + pubJwk.y)))].map(x => x.toString(16).padStart(2, '0')).join('');
  return h.slice(0, 20).match(/.{4}/g).join(' ');
}
/* a few seconds of work at sign-up; trivial for a person, costly for a bot farm */
async function solvePow(challenge, bits) {
  for (let i = 0; ; i++) {
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(challenge + ':' + i)));
    let zeros = 0; for (const byte of d) { if (byte === 0) zeros += 8; else { zeros += Math.clz32(byte) - 24; break; } }
    if (zeros >= bits) return String(i);
    if (i % 4000 === 0) await new Promise(r => setTimeout(r));
  }
}
