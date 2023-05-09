"use strict";

const workerpool = require('workerpool');
const { modInverse, gcd, seededRandPrime } = require('./utils');

// https://github.com/digitalbazaar/forge/blob/master/lib/prime.worker.js#L14
const SMALL_PRIMES = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n,
    59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n,
    137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n, 199n, 211n,
    223n, 227n, 229n, 233n, 239n, 241n, 251n, 257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n,
    307n, 311n, 313n, 317n, 331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n,
    397n, 401n, 409n, 419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n, 467n, 479n,
    487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n, 547n, 557n, 563n, 569n, 571n, 577n, 587n,
    593n, 599n, 601n, 607n, 613n, 617n, 619n, 631n, 641n, 643n, 647n, 653n, 659n, 661n, 673n,
    677n, 683n, 691n, 701n, 709n, 719n, 727n, 733n, 739n, 743n, 751n, 757n, 761n, 769n, 773n,
    787n, 797n, 809n, 811n, 821n, 823n, 827n, 829n, 839n, 853n, 857n, 859n, 863n, 877n, 881n,
    883n, 887n, 907n, 911n, 919n, 929n, 937n, 941n, 947n, 953n, 967n, 971n, 977n, 983n, 991n,
    997n];
/**
 * Deterministically generates RSA keys from seeds
 * @param {number} bits Number of bits the modulus will contain
 * @param {Uint8Array} seed 32 byte Uint8Array for seeding prime generation
 * @param {BigInt} e Public encryption exponent to be stored in public key
 * @returns {privateKey: {JsonWebKey}, publicKey: {JsonWebKey}} A public and private JWK
 */
async function rsaGenKeys(bits, seed, e = 65537n) {
    if (bits % 32) throw Error("bits must be a multiple of 32");
    if (bits < 192) throw Error("bits must be at least 192");
    if (seed.length < 32) throw Error("seed must contain at least 32 bytes");

    // Initialize prime generation
    const pBits = bits >> 1;
    const qBits = bits - pBits;
    const pSeed = new Uint8Array(seed.slice(0, 16));
    const qSeed = new Uint8Array(seed.slice(16, 32));

    // Generate primes multithreaded
    const pool = workerpool.pool()
    let [p, q] = await Promise.all([
        pool.exec(seededRandPrime, [pBits, pSeed, e, SMALL_PRIMES]),
        pool.exec(seededRandPrime, [qBits, qSeed, e, SMALL_PRIMES])
    ]);
    pool.terminate();


    const n = p * q; // Public modulus
    if (n.toString(2).length != bits) throw Error("Generation resulted in an incorrect modulus");

    const p1 = p - 1n;
    const q1 = q - 1n;
    const phi = p1 * q1; // aka mod coprimes, or euler's totient
    if (gcd(phi, e) !== 1n) throw Error("Phy and e were not coprime"); // Check for phi-e coprimality

    if (q === p) throw Error("q and p were the same, heat death of universe before this happens");

    // Ensure p > q, otherwise swap (fast xor swap)
    if (q > p) {
        p ^= q;
        q ^= p;
        p ^= q;
    }

    // https://github.com/rzcoder/node-rsa/blob/master/src/libs/rsa.js#L93
    // https://self-issued.info/docs/draft-jones-jose-json-private-and-symmetric-key-00.html
    const d = modInverse(e, phi);
    const dp = d % p1;
    const dq = d % q1;
    const qi = modInverse(q, p);


    // Convert to JWK 
    // https://coolaj86.com/articles/bigints-and-base64-in-javascript/
    // https://tools.ietf.org/id/draft-jones-json-web-key-01.html#rfc.section.5
    // https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    // https://github.com/ipfs-shipyard/js-human-crypto-keys/blob/master/src/keys/rsa.js#L14-L36
    // https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L1149
    // https://self-issued.info/docs/draft-jones-jose-json-private-and-symmetric-key-00.html
    return {
        privateKey: {
            "d": d,
            "p": p,
            "q": q,
            "dp": dp,
            "dq": dq,
            "qi": qi
        },
        publicKey: {
            "n": n,
            "e": e
        }
    };
}



module.exports = { rsaGenKeys };