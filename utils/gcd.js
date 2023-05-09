
/**
 * Get the greatest common divisor
 * Can be improved https://en.wikipedia.org/wiki/Lehmer%27s_GCD_algorithm
 * @param {BigInt} a 
 * @param {BigInt} b Must be smaller than a
 * @returns {BigInt} Greatest common divisor
 */
module.exports = function (a, b) {
    while (true) {
        if (b === 0n) return a;
        a %= b;
        if (a === 0n) return b;
        b %= a;
    }
}