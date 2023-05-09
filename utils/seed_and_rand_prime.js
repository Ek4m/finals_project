/**
 * Generates a random prime given a 32bit number seed
 * @param {number} bits How many bits the prime will contain, ceiled to multiple of 32
 * @param {Uint8Array} seed 16 byte Uint8Array for seeding prime generation
 * @param {BigInt} exp RSA Exponent, use to check coprimality
 * @param {Array<number>} SMALL_PRIMES Array of pre-generated primes to validate against
 * @returns {BigInt} Prime number of size bits
 */
module.exports = function (bits, seed, exp, small_primes) {
    if (bits < 96) throw Error("Bits must be at least 96");
    if (seed.length < 16) throw Error("Seed byte buffer must be at least 16 bytes");

    const dataView = new DataView(seed.buffer);
    let rand_a = dataView.getUint32(0);
    let rand_b = dataView.getUint32(4);
    let rand_c = dataView.getUint32(8);
    let rand_d = dataView.getUint32(12);
    let rand_t, rand_r;

    /**
     * Generates a 32 bit random number
     * https://stackoverflow.com/a/47593316/12802155
     * @returns {number} A number of at least 32 random bits
     */
    function xoshiro128ss() {
        rand_t = rand_b << 9, rand_r = rand_a * 5; rand_r = (rand_r << 7 | rand_r >>> 25) * 9;
        rand_c ^= rand_a; rand_d ^= rand_b;
        rand_b ^= rand_c; rand_a ^= rand_d; rand_c ^= rand_t;
        rand_d = rand_d << 11 | rand_d >>> 21;
        return rand_r >>> 0;
    }

    /**
     * Checks if a BigInt is probably prime
     * https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#JavaScript
     * @param {BigInt} n The BigInt to test for primality
     * @param {number} k How many rounds to test the number, each round increases confidence by 75%
     * @returns {boolean} True means it"s probably prime, false meaning composite
     */
    function millerRabin(n, k) {
        // Write (n - 1) as 2^s * d
        let s = 0, d = n - 1n;
        while (d % 2n === 0n) {
            d /= 2n;
            ++s;
        }

        WitnessLoop: do {
            // A base between 2 and n - 2
            let x = modExp(BigInt(xoshiro128ss()) + 2n, d, n);
            if (x === 1n || x === n - 1n) continue;

            // b1 to bk
            for (let i = s - 1; i--;) {
                x = modExp(x, 2n, n);
                if (x === 1n)
                    return false;
                if (x === n - 1n)
                    continue WitnessLoop;
            }

            return false;
        } while (--k);

        return true;
    }

    /**
     * Returns the required number of Miller-Rabin tests to generate a prime with an error probability of (1/2)^80.
     * https://github.com/digitalbazaar/forge/blob/c666282c812d6dc18e97b419b152dd6ad98c802c/lib/prime.worker.js#L155
     * @param {number} bits Bit size
     * @returns {number} The required number of iterations.
     */
    function getMillerRabinTests(bits) {
        if (bits <= 100) return 27;
        if (bits <= 150) return 18;
        if (bits <= 200) return 15;
        if (bits <= 250) return 12;
        if (bits <= 300) return 9;
        if (bits <= 350) return 8;
        if (bits <= 400) return 7;
        if (bits <= 500) return 6;
        if (bits <= 600) return 5;
        if (bits <= 800) return 4;
        if (bits <= 1250) return 3;
        return 2;
    }

    /**
     * Performs modular exponentiation (a ^ b % n)
     * https://gist.github.com/krzkaczor/0bdba0ee9555659ae5fe
     * @param {BigInt} a Base
     * @param {BigInt} b Exponent
     * @param {BigInt} n Modulus
     * @returns {BigInt} Result of the operation
     */
    function modExp(a, b, n) {
        a = a % n;
        let result = 1n;
        let x = a;
        while (b > 0) {
            let leastSignificantBit = b & 1n;
            b = b / 2n;
            if (leastSignificantBit === 1n) {
                result = result * x;
                result = result % n;
            }
            x = x * x;
            x = x % n;
        }
        return result;
    };

    /**
     * Get the greatest common divisor
     * Can be improved https://en.wikipedia.org/wiki/Lehmer%27s_GCD_algorithm
     * @param {BigInt} a 
     * @param {BigInt} b Must be smaller than a
     * @returns {BigInt} Greatest common divisor
     */
    function gcd(a, b) {
        while (true) {
            if (b === 0n) return a;
            a %= b;
            if (a === 0n) return b;
            b %= a;
        }
    }


    const bytes = Math.ceil(bits / 32) * 4;
    bits = bytes * 8;

    // Generate a random BigInt, assumes at least 96 bits and bits are multiple of 32
    let primeCand = BigInt((xoshiro128ss() | 0xC0000000) >>> 0) << BigInt(bits - 32); // Set 2 MSBs to 1 to guarantee product bit length
    for (let bitShift = BigInt(bits - 64); bitShift > 0n; bitShift -= 32n)
        primeCand |= BigInt(xoshiro128ss()) << bitShift;
    primeCand |= BigInt((xoshiro128ss() | 1) >>> 0); // Set LSB to 1 to guarantee odd

    let composite, randShift;
    for (; ;) {
        // Check primality
        composite = false;
        for (let i = 0; i < small_primes.length; ++i)
            if (primeCand % small_primes[i] === 0n) {
                composite = true;
                break;
            }
        if (
            !composite &&
            millerRabin(primeCand, getMillerRabinTests(bits)) &&
            gcd(primeCand - 1n, exp) === 1n // Check prime - 1 is coprime with exponent
        ) return primeCand;

        // BigInt wasn't valid, flip a random bit (excluding 2 MSB and LSB)
        randShift = xoshiro128ss() % (bits - 3) + 1;
        primeCand ^= 1n << BigInt(randShift);
    }
}