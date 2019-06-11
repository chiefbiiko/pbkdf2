import { SHA1 } from "https://denopkg.com/chiefbiiko/sha1/mod.ts";
import { SHA256 } from "https://denopkg.com/chiefbiiko/sha256/mod.ts";
import { SHA512 } from "https://denopkg.com/chiefbiiko/sha512/mod.ts";
import { HMAC } from "https://denopkg.com/chiefbiiko/hmac/mod.ts";

const encoder: TextEncoder = new TextEncoder();

const SHA1_REGEX: RegExp = /^\s*sha-?1\s*$/i;
const SHA256_REGEX: RegExp = /^\s*sha-?256\s*$/i;
const SHA512_REGEX: RegExp = /^\s*sha-?512\s*$/i;

/** An interface representation of a keyed hash algorithm implementation. */
export interface KeyedHash {
  hashSize: number;
  init(key: Uint8Array): KeyedHash;
  update(msg?: Uint8Array): KeyedHash;
  digest(msg?: Uint8Array): Uint8Array;
}

/** A class representation of the PBKDF2 algorithm. */
export class PBKDF2 {
  private hmac: KeyedHash;
  private rounds: number = 1000;

  /** Creates a new PBKDF2 instance. */
  constructor(hmac: KeyedHash, rounds: number = 10000) {
    this.hmac = hmac;
    this.rounds = rounds;
  }

  /** Derives a key. */
  derive(password: Uint8Array, salt: Uint8Array, length?: number): Uint8Array {
    let u: Uint8Array;
    let ui: Uint8Array;
    length = length || this.hmac.hashSize >>> 1;
    const out: Uint8Array = new Uint8Array(length);
    for (
      let k: number = 1, len: number = Math.ceil(length / this.hmac.hashSize);
      k <= len;
      ++k
    ) {
      u = ui = this.hmac
        .init(password)
        .update(salt)
        .digest(
          new Uint8Array([
            (k >>> 24) & 0xff,
            (k >>> 16) & 0xff,
            (k >>> 8) & 0xff,
            k & 0xff
          ])
        );
      for (let i: number = 1; i < this.rounds; i++) {
        ui = this.hmac.init(password).digest(ui);
        for (let j: number = 0; j < ui.length; j++) {
          u[j] ^= ui[j];
        }
      }
      // append data
      out.set(
        u.subarray(
          0,
          k * this.hmac.hashSize < length
            ? this.hmac.hashSize
            : length - (k - 1) * this.hmac.hashSize
        ),
        (k - 1) * this.hmac.hashSize
      );
    }
    return out;
  }

  // /**
  //  * Performs a quick selftest
  //  * @return {Boolean} True if successful
  //  */
  // selftest(): boolean {
  //   const tv = {
  //     key:    'password',
  //     salt:   'salt',
  //     c:      2,
  //     sha256: 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
  //   };
  //
  //   let pbkdf2_sha256 = new PBKDF2(new HMAC(new SHA256()), tv.c);
  //   let key = Convert.str2bin(tv.key);
  //   let salt = Convert.str2bin(tv.salt);
  //   let mac = pbkdf2_sha256.hash(key, salt, Convert.hex2bin(tv.sha256).length);
  //   return Convert.bin2hex(mac) === tv.sha256;
  // }
}

/** Derives a key from a password and salt using the indicated hash. */
export function pbkdf2(
  hash: string,
  password: string | Uint8Array,
  salt: string | Uint8Array,
  length?: number,
  rounds?: number
): Uint8Array {
  if (typeof password === "string") {
    password = encoder.encode(password);
  }
  if (typeof salt === "string") {
    salt = encoder.encode(salt);
  }
  if (SHA1_REGEX.test(hash)) {
    return new PBKDF2(new HMAC(new SHA1()), rounds).derive(
      password,
      salt,
      length
    );
  } else if (SHA256_REGEX.test(hash)) {
    return new PBKDF2(new HMAC(new SHA256()), rounds).derive(
      password,
      salt,
      length
    );
  } else if (SHA512_REGEX.test(hash)) {
    return new PBKDF2(new HMAC(new SHA512()), rounds).derive(
      password,
      salt,
      length
    );
  } else {
    throw new TypeError(
      `Unsupported hash ${hash}. Must be one of SHA(1|256|512).`
    );
  }
}
