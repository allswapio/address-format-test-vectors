import { inspectAddress } from "multichain-memo-address-validator";

console.log(await inspectAddress("bch", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
console.log(await inspectAddress("btc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"));
console.log(await inspectAddress("btc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 "));
console.log(await inspectAddress("xrp", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
