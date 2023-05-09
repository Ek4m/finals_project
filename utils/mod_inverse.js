
/**
 * Mod Inverse, aka EEA / EGCD optimized for only finding coefficient of A
 * https://stackoverflow.com/a/27736785/5623318
 * Maybe can be improved
 *  - https://math.stackexchange.com/a/3839960/925321
 *  - https://en.wikipedia.org/wiki/Hensel%27s_lemma
 * @param {BigInt} exp e, Public encryption exponent to be stored in public key
 * @param {BigInt} phi 
 * @returns {BigInt} d, Decryption exponent to be stored in private key
 */
module.exports = function (exp, phi) {
    let q, t1, t3;
    let u1 = 1n;
    let u3 = exp;
    let v1 = 0n;
    let v3 = phi;
    let iter = 1n;
    while (v3 !== 0n) {
        q = u3 / v3;
        t3 = u3 % v3;
        t1 = u1 + q * v1;
        u1 = v1; // Maybe try wrapping js values in object to swap references instead of large copies in heap
        v1 = t1;
        u3 = v3;
        v3 = t3;
        iter = -iter;
    }
    if (u3 != 1n) return 0n;
    return iter > 0n ? u1 : phi - u1;
}