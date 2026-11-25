// 把 inspectAddress 的結果轉成給使用者看的提示。Node.js 22。
// 規則：先去掉頭尾空白再驗證（函式庫本身不會 trim）；「格式正確」與「需要備註」分開講。
import { inspectAddress } from "multichain-memo-address-validator";

const FAMILY_HINT = {
  xrp: "XRP 的目的地標籤（Destination Tag）",
  stellar: "Stellar 的備註（Memo）",
  ton: "TON 的備註（Comment）",
  near: "NEAR 的備註（Memo，視對方平台而定）",
};

export async function addressFeedback(chain, rawInput) {
  const input = rawInput.trim();
  const trimmed = input !== rawInput;
  const r = await inspectAddress(chain, input);
  if (r === null) return { level: "error", code: "unknown-chain", message: `不認得的鏈：${chain}` };
  if (!r.valid) {
    const byPitfall = {
      "xrp-x-address": "這是 X-address（可以內含目的地標籤）；本檢查只收一般 r... 位址，請改用一般位址，標籤另外填",
      "ltc-legacy-3-prefix": "3 開頭的字串在 Bitcoin 是合法的，但本檢查不收作 Litecoin 位址，請向對方確認",
      "bch-legacy-base58": "這是舊式 Base58 位址，與 Bitcoin 位址的編碼相同；本檢查只收 CashAddr",
      "ton-testnet-or-masterchain": "這是測試網或 masterchain 的 TON 位址形式",
      "evm-bad-checksum": "大小寫不符合 EIP-55 檢查碼，可能有字元被改過",
      whitespace: "位址中間含有空白或換行",
    };
    return { level: "error", code: r.pitfall, message: byPitfall[r.pitfall] ?? "格式不正確" };
  }
  const notes = [];
  if (trimmed) notes.push("已自動去掉頭尾空白");
  if (r.checksum === "unchecked-case") notes.push("全小寫或全大寫的 EVM 位址沒有檢查碼可驗，請再核對一次");
  if (r.memoSensitive) notes.push(`${FAMILY_HINT[r.family]}無法從位址判斷是否必填：請向收款方確認`);
  return { level: notes.length ? "warn" : "ok", code: r.pitfall, message: notes.join("；") || "格式正確" };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cases = [
    ["btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
    ["btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "],
    ["evm", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"],
    ["xrp", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"],
    ["xrp", "XVLhHMPHU98es4dbozjVtdWzVrDjtV5fdx1mHp98tDMoQXb"],
    ["stellar", "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"],
    ["bch", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
  ];
  for (const [chain, address] of cases) {
    const f = await addressFeedback(chain, address);
    console.log(`${chain.padEnd(7)} ${JSON.stringify(address).slice(0, 30).padEnd(30)} ${f.level.padEnd(5)} ${f.message}`);
  }
}
