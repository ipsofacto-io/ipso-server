// An EDR names itself with a ULID (edr-spec, draft 0.2): 48 bits of time and 80 random bits, in Crockford base32,
// so the id sorts by the time it was made. The first character is 0 to 7 because the time takes 48 of 50 bits.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function fillWithRandom(bytes: Uint8Array): void {
  crypto.getRandomValues(bytes);
}

/** Makes a ULID. `random` fills the bytes it is given, and a test passes its own. */
export function newUlid(now: number = Date.now(), random: (bytes: Uint8Array) => void = fillWithRandom): string {
  let time = Math.floor(now);
  if (!Number.isSafeInteger(time) || time < 0 || time >= 2 ** 48) throw new RangeError('A ULID holds a time of 48 bits.');
  let head = '';
  for (let i = 0; i < 10; i += 1) {
    head = ALPHABET.charAt(time % 32) + head;
    time = Math.floor(time / 32);
  }

  const bytes = new Uint8Array(10);
  random(bytes);
  let tail = '';
  let value = 0;
  let bits = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      tail += ALPHABET.charAt((value >> (bits - 5)) & 31);
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  return head + tail;
}
