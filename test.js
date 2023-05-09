"use strict";

const bip39 = require("bip39");
const detRsa = require("./index");

const start = (new Date()).getTime();

main().then((result) => {
    console.log(result);
    console.log("Took", ((new Date()).getTime() - start) / (1000), "seconds on average");
});

async function main() {

    const mnemonic = "violin artwork lonely inject resource jewel purity village abstract neglect panda license"
    // return await detRsa.rsaGenKeys(4096, seed);

    // Takes ~5 seconds on average, can probably be improved to 3
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const res = await detRsa.rsaGenKeys(4096, seed);
    return res;
}