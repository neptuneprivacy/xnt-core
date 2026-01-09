/**
 * XNT-SDK TypeScript Test
 *
 * Usage: npx ts-node examples/xnt-sdk-test.ts [command]
 * Commands: version, seed, address, rpc, sync, utils, tx, full
 */

import {
  XntNetwork,
  XntWalletEntropy,
  XntAddress,
  XntRpcClient,
  XntTransactionBuilder,
  XntMembershipProof,
  XntDecryptedUtxo,
  XntPendingUtxo,
  xntVersion,
  xntTimestampNow,
  xntFetchUtxos,
  xntCheckSpent,
  xntGetAoclIndices,
  xntGetMutatorSet,
  xntGetMembershipProofs,
  xntDecryptIndexedUtxo,
  xntComputeCommitment,
  xntComputeAbsoluteIndexSetHash,
  xntRandomSenderRandomness,
  xntSelectInputs,
  xntMempoolSpending,
  xntMempoolIncoming,
  xntComputeCommitmentForOutput,
} from "../src/napi/output";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} required`);
  return value;
}

const TEST_MNEMONIC = requireEnv("XNT_TEST_MNEMONIC");
const RPC_URL = requireEnv("XNT_RPC_URL");

const log = console.log;
const ok = (msg: string) => log(`[OK] ${msg}`);
const fail = (msg: string) => { log(`[FAIL] ${msg}`); return false; };
const skip = (msg: string) => { log(`[SKIP] ${msg}`); return false; };

const CONVERSION_FACTOR = 4n * 10n ** 30n; // 1 XNT = 4 * 10^30 NAU
const toNau = (xnt: number) => BigInt(Math.round(xnt * 1e8)) * CONVERSION_FACTOR / 100000000n;
const formatAmount = (nau: bigint) => {
  const abs = nau < 0n ? -nau : nau;
  const sign = nau < 0n ? "-" : "";
  return `${sign}${abs / CONVERSION_FACTOR}.${((abs % CONVERSION_FACTOR) * 100000000n / CONVERSION_FACTOR).toString().padStart(8, "0")} XNT`;
};

interface UnspentUtxo {
  decrypted: XntDecryptedUtxo;
  aoclIndex: number;
  absHash: string;
}

interface SyncResult {
  unspent: UnspentUtxo[];
  pendingSpending: number[];  // indices into unspent that are pending spend
  pendingIncoming: XntPendingUtxo[];
}

function syncWallet(client: XntRpcClient, key: ReturnType<XntWalletEntropy["deriveKey"]>): SyncResult | null {
  const ridHashHex = key.receiverIdHashHex();
  const receiverPreimageHex = key.receiverPreimageHex();

  const height = client.chainHeight();
  if (height < 0) return null;

  // Fetch & decrypt all UTXOs
  const decrypted: XntDecryptedUtxo[] = [];
  for (let from = 0; from <= height; from += 1000) {
    const indexed = xntFetchUtxos(client, ridHashHex, from, Math.min(from + 999, height));
    for (const u of indexed) {
      try {
        decrypted.push(xntDecryptIndexedUtxo(key, u.ciphertext, u.blockHeight, u.blockDigestHex));
      } catch { /* not ours */ }
    }
  }
  if (decrypted.length === 0) return { unspent: [], pendingSpending: [], pendingIncoming: [] };

  // Get AOCL indices
  const commitments = decrypted.map(u =>
    xntComputeCommitment(u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex)
  );
  const aoclIndices = xntGetAoclIndices(client, commitments);

  // Check spent status for valid UTXOs
  const validUtxos: { idx: number; aocl: number; absHash: string }[] = [];
  aoclIndices.forEach((aocl, i) => {
    if (aocl >= 0) {
      const u = decrypted[i];
      const absHash = xntComputeAbsoluteIndexSetHash(u.utxo.hashHex(), u.senderRandomnessHex, receiverPreimageHex, aocl);
      validUtxos.push({ idx: i, aocl, absHash });
    }
  });

  const spentStatus = xntCheckSpent(client, validUtxos.map(v => v.absHash));
  const now = BigInt(Date.now());

  // Filter unspent and spendable (not timelocked)
  const unspent = validUtxos
    .filter((_, j) => spentStatus[j] < 0)
    .map(v => ({ decrypted: decrypted[v.idx], aoclIndex: v.aocl, absHash: v.absHash }))
    .filter(u => u.decrypted.utxo.canSpendAt(now));

  // Check mempool for pending spending
  const absHashes = unspent.map(u => u.absHash);
  let pendingSpending: number[] = [];
  try {
    pendingSpending = xntMempoolSpending(client, absHashes);
  } catch { /* mempool check failed, ignore */ }

  // Check mempool for pending incoming
  let pendingIncoming: XntPendingUtxo[] = [];
  try {
    pendingIncoming = xntMempoolIncoming(client, key);
  } catch { /* mempool check failed, ignore */ }

  return { unspent, pendingSpending, pendingIncoming };
}


function testVersion(): boolean {
  log("Testing version...");
  ok(`version: ${xntVersion()}`);
  return true;
}

function testSeed(): boolean {
  log("\nTesting seed...");

  const wallet = new XntWalletEntropy(TEST_MNEMONIC);
  ok("imported");

  if (wallet.toMnemonic() !== TEST_MNEMONIC) return fail("mnemonic mismatch");
  ok("roundtrip");

  const key = wallet.deriveKey(0);
  ok(`receiver_id: ${key.receiverIdHex()}`);

  const gen = XntWalletEntropy.generate();
  ok(`generated ${gen.toMnemonic().split(" ").length} words`);

  return true;
}

function testAddress(): boolean {
  log("\nTesting address...");

  const wallet = new XntWalletEntropy(TEST_MNEMONIC);
  const addr = wallet.deriveKey(0).toAddress();

  const bech32 = addr.toBech32(XntNetwork.Main);
  ok(`bech32: ${bech32}`);

  const decoded = XntAddress.fromBech32(bech32, XntNetwork.Main);
  if (decoded.toBech32(XntNetwork.Main) !== bech32) return fail("roundtrip");
  ok("roundtrip");

  const sub = addr.withPaymentId(12345);
  const subBech32 = sub.toBech32(XntNetwork.Main);
  ok(`subaddress payment_id=${sub.paymentId()}: ${subBech32}`);

  try { addr.withPaymentId(0); return fail("should reject payment_id=0"); }
  catch { ok("rejected payment_id=0"); }

  return true;
}

function testRpc(): boolean {
  log("\nTesting RPC...");

  let client: XntRpcClient;
  try { client = new XntRpcClient(RPC_URL); } catch { return skip("no server"); }

  try { client.ping(); ok("ping"); } catch { return skip("ping failed"); }
  ok(`height: ${client.chainHeight()}`);

  return true;
}

function testSync(): boolean {
  log("\nTesting sync...");

  const wallet = new XntWalletEntropy(TEST_MNEMONIC);
  const key = wallet.deriveKey(0);

  let client: XntRpcClient;
  try { client = new XntRpcClient(RPC_URL); client.ping(); } catch { return skip("no server"); }

  const result = syncWallet(client, key);
  if (!result) return skip("sync failed");

  ok(`found ${result.unspent.length} unspent UTXOs`);

  let total = 0n;
  const receiverPreimage = key.receiverPreimageHex();
  const privacyDigest = key.toAddress().privacyDigestHex();

  log("\n  Unspent UTXOs:");
  for (let i = 0; i < result.unspent.length; i++) {
    const u = result.unspent[i];
    const d = u.decrypted;
    total += d.amount;
    const pending = result.pendingSpending.includes(i) ? " [PENDING SPEND]" : "";
    const c = xntComputeCommitment(d.utxo.hashHex(), d.senderRandomnessHex, receiverPreimage);
    const pid = d.paymentId ? `, pid=${d.paymentId}` : "";
    log(`    aocl=${u.aoclIndex}, h=${d.blockHeight}, amt=${formatAmount(d.amount)}${pid}${pending}, c=${c}`);
  }

  // Show pending incoming
  let incomingTotal = 0n;
  if (result.pendingIncoming.length > 0) {
    log(`\n  Pending Incoming (${result.pendingIncoming.length}):`);
    for (const p of result.pendingIncoming) {
      incomingTotal += p.amount;
      const c = xntComputeCommitmentForOutput(p.utxo.hashHex(), p.senderRandomnessHex, privacyDigest);
      const pid = p.paymentId > 0 ? `, pid=${p.paymentId}` : "";
      log(`    amt=${formatAmount(p.amount)}${pid}, c=${c}`);
    }
  }

  // Calculate pending spending total
  let spendingTotal = 0n;
  for (const idx of result.pendingSpending) {
    spendingTotal += result.unspent[idx].decrypted.amount;
  }

  // Balance summary
  const available = total - spendingTotal;
  const unconfirmed = available + incomingTotal;
  log(`\n  Balance: ${formatAmount(total)}`);
  if (incomingTotal > 0n || spendingTotal > 0n) {
    log(`  Unconfirmed: ${formatAmount(unconfirmed)}`);
  }

  return true;
}

function testUtils(): boolean {
  log("\nTesting utils...");
  ok(`timestamp: ${xntTimestampNow()}`);
  ok(`random sender_randomness: ${xntRandomSenderRandomness().slice(0, 16)}...`);
  return true;
}

function testTx(): boolean {
  log("\nTesting transaction (build & prove)...");

  const wallet = new XntWalletEntropy(TEST_MNEMONIC);
  const key = wallet.deriveKey(0);
  const addr = key.toAddress();

  let client: XntRpcClient;
  try { client = new XntRpcClient(RPC_URL); client.ping(); } catch { return skip("no server"); }

  // Sync wallet
  const result = syncWallet(client, key);
  if (!result || result.unspent.length === 0) return skip("no unspent UTXOs");
  ok(`found ${result.unspent.length} unspent UTXOs`);

  // Filter out pending spending UTXOs
  const available = result.unspent.filter((_, i) => !result.pendingSpending.includes(i));
  if (available.length === 0) return skip("all UTXOs pending spend");
  if (available.length < result.unspent.length) {
    ok(`${result.unspent.length - available.length} UTXOs pending spend, ${available.length} available`);
  }

  // Select inputs
  const fee = toNau(0.005);
  const sendAmount = toNau(0.575);
  const totalAmount = sendAmount + fee;

  const amounts = available.map(u => u.decrypted.amount);
  const selected = xntSelectInputs(amounts, totalAmount, 10);
  ok(`selected ${selected.length} UTXOs for ${formatAmount(totalAmount)}`);

  // Get membership proofs for selected
  const selectedUtxos = selected.map(i => available[i]);
  const proofBuffers = xntGetMembershipProofs(
    client,
    selectedUtxos.map(u => u.decrypted.utxo.hashHex()),
    selectedUtxos.map(u => u.decrypted.senderRandomnessHex),
    key.receiverPreimageHex(),
    selectedUtxos.map(u => u.aoclIndex)
  );
  ok(`got ${proofBuffers.length} membership proofs`);

  // Build transaction
  const mutatorSet = xntGetMutatorSet(client);
  const builder = new XntTransactionBuilder();

  for (let i = 0; i < selected.length; i++) {
    const proof = XntMembershipProof.fromBytes(proofBuffers[i]);
    builder.addInput(selectedUtxos[i].decrypted.utxo, key, proof);
  }

  // Send to recipient address (edit this address string as needed)
  const RECIPIENT_ADDRESS = "xntsam1fukfru30yfx8vgr5qc7twg7ghsm7ck4m4943elkdzknyz66lswejf2d3uzx6g929zza7pvqye3zx8y3zjgfmktzrqjlhg5823wx0nmnr8a2nkj8lhfskfd692yzwa38l882nwvc5vvlnuu27alrnljs9whfks8tncshpdel6tv8cyfmqrd2xef9vlmr5k9py7n5h9yne07znm22jt8wxalleydetpjpj6dy3fuv9kyl6c8sv76zuw6ff2jwjervrzh6t8jmt0mgnle6v20nwygu9qnu3r5xmagtnew278ect08hys9yz9cf9anc7uwr4w945cxf4evhqgux83gf3k2prq40v3u97qhsjqae90s72pju69zh4752mzvwgm426yr2p3ag5m7zeuf0wgcuyztr9vw8ua5kpl8v8gypqhxpzav0ccp8he5mmfss007vykgqydhz528agu6vju9k3cnxywhpjskhkrfmw6gjx42kdksvlz8dhcvzl27gey6trvevscfmj94rl7cwnnr2tllumc9suv9as2xfkklfj4xdnv8y3fax3wcmqx8vyha5jnmt5cw2hjk6034vddanadzvy04k7g5d6tx2qmtmtjuatu8vjh7sq3uwm75zk5qygh3ye7pwxuutxk53vv3aae7kmndstwlhcg6km7st90xl5ecn65htnn8aju8pj5n4kex43pln80n9lz6u56yu39q67wq233dynql5zff3ndc27xaq2vc8vz3xn5xjpr0mc9znrcmed0wu5sx7sngzdl2w8986jsyn48wnveca9mdn5wlunqe8wwznwk5krx5rscp2f3sw604hm7wct6tpaxe7l5v6l9hgglhjyymslthx0l8xadkg6a4dcejgttkq9ak9gr23gq42g73cy8h5x9wjv24ayqsyecrnt8cg0g3c3kw2kc7xydwfmh934flkhxyl6hdermdn7nv9806d93d8vyxmad8urhy0smglxv99awqf8kwku3w49hg5v0khd37pg2rc5tf737qqfgfd8je6nqtknw4t98x5tdqen8gj06dylt586mrcjermlu7d3r0x7mnvrr9dfn73qeng5ccj9tm3nzcmnrame6kwsg48tczvv0d46ykk5m6kmy2z967sc0v23m0gqe0w7fy7c4q8y66405m0rvwqrdws66ek3kuyju0hz4h929snhcn0yj3dd54e4qrm0ymxurw0uxh82w2h0jf0sqly0dtt3z4xn0qvpf3letk772zdvlmsmg74k2ge96t4ttaavw6hc9yylpx62kjg77lrg7r57j9arakxgfwxu8wkm3rfrv442797wl9wm4m27vfeg9u6ff8zlceax8mrrfvyzezf5uuuadvcvgt7wfdvtgm3926nh9txzlu4yg3dhdm92zqdusyjwzdrlfggdypmgp25vtxzl2ut6pvupvra0mdnfekjpagrln7nl4vqz69c6cn6z0xmn5dvsg6fx2dukyk3cpvd6ka04avmnxru7nghd0pzzuhc2j0a3vnnwuc3xxjmvlxsld5w92q33u46sr9kt73vwdkf6t36q96hxxfsgj26we3pks6cd3ku8krelalcn94tdpkdy8889qy9dc5aqk7lnal499nhqgeh7a70fm0nju5r23583u059pazck4grpklanczq9r26a4vz4hygmswc2z8m3sxj5n3l0v8ezq6nf7elhmylqeytazt39na3s0kfuq0s2q9yrw5y4y04v9r7shj8w80xdy4yqrl2kkhz8amzd7t7w6n5yzskhd2yurwm70amkqxsvut689plyjc9lc8k7c4477sfg30l4g9633nnyyg8kdgj2w6hud2ee5zyjw3cpghhumpq6as8a0dwtqctqgyuef2yzyfcfcpu234h8x2yqaxxmxgqnlqm2235vsm7sar6xva2yqq75yelsdnp9xxy4qmf787xd3yd5s8nn3pxskj3yx7glywjhwuv26jku420c84qx7sd596ydp9j34def6thy4nvw2ctypg9qvcuaythfl0qj789f03tt0m78cwumahut4q5fqyv0kq9tvwfm42qx0sx9wq9wd5atwwfawrvrc5jxf887sydncyz3m6x0yus8nu2a78s6p9gdx3dtnrk07w3anrp0ra2laj5adz4gady7ept70lflr32jp7jzj5a3ee4j6ff95rm54qtxw4e793zs25xpz0k5at7ceh8pym5zd6y7uxgd0us8t5v2kqgzp6eg2md8ktekvz85vnlqp7kc9cschw3s5vrdxwpd4467p53a7093yxturp0eckcgn0tzqxse5u0uwp2rvxv94jfes2he607ud8rtq8g0sh2vj0v9vw0lfftkcd6medp60u4rvnkrlwj5dv06z66elmnlee3p8xzwmds20q4yutakx7f2s75dmxsdf6hvjv5yrv0nwdaeehwd7s97vqfpyr6579kvkr6tex5wd0k8ahukhy0lr8wh346sjzxh29uxz2censsr38sm24pjrv2tttnvtrewdgd7ftpjnnuqkuatth4a8lsp20n6vatrmqzpnqn4erwfkhcst9g7lkk9c50z3lgulhz7c6yvwr0uhmsef8p2w7r5hefpave8fskgwcmqrgwz3e7935luds7mfk8uz53eywmrnc004p6mrsqujr6gprkyxqpltuqnk8cet5t84lsvs3lqhxvxm8wnv4npk4rlt47gntc4mpzsl3zz5gkquaqkjlgsc0tkt8sh5zff4jn48l7dxg84y4g9t627t79jymqltdw9d0929z803xy7gn5nz5pj0nsdheklytssm5d3hvyjmklp56wrfv4z6zg79k9a0529pgcrmfwq6tzf96jrxs962u2yhfyx3td5qzd6nplnrkdd8ur93zxzehnsc26zca6dmdrp9mvtfarx3l570cs707dztk3e9s2qy7zvg0tjmfp0u3hd9g9ka0u8sup554csxkx88cf36psn4rz63m705er27lp63jsgp72qqwmzatyrhl8sq24xvkz9s67lncyy30l9zgz052l77dlnxjzf4e9prwcdarkaklplnn8u5vh8yjc38hrwjh6us9nlz93h05qf2jtq45yr8pmk8zyn34378pqrg9tlazdaaex5ax6c9ffgmjrq0l6762hyyvf6nhn0mn7aga58mu74prctc59w44wjq8tqv89deue479ycx98zl20nxft6nn9dn6z640wez0sydv0yx08yct6smgedltj6x0wqacyl70sxtztxr860px6f2tsvgrd92a4t0gwhwdhz4j9znhl2fcxl87t585cgdpesg3y2ffnar98wkaqj3l9r37mktrr3ju85a6p954duqehaxsqjhpr2dmq0pmspw2wn74a7vwm0jx24y6emz6agj2hkt0cjn4c89wygwzmqyqqqqqqqq6r0cka"; // placeholder - replace with valid bech32 address
  const recipient = XntAddress.fromBech32(RECIPIENT_ADDRESS, XntNetwork.Main);
  builder.addOutput(recipient.toReceivingAddress(), sendAmount, xntRandomSenderRandomness());
  builder.setFee(fee);
  builder.setChange(addr, xntRandomSenderRandomness());

  const builtTx = builder.build(mutatorSet, xntTimestampNow(), XntNetwork.Main);

  // Print summary
  const inputs = builtTx.inputs();
  const outputs = builtTx.outputs();
  log(`\n  Inputs (${inputs.length}): ${formatAmount(inputs.reduce((s, i) => s + i.amount, 0n))}`);
  for (const inp of inputs) {
    log(`    ${formatAmount(inp.amount)}, c=${inp.commitmentHex}`);
  }
  log(`  Outputs (${outputs.length}): ${formatAmount(outputs.reduce((s, o) => s + o.amount, 0n))}`);
  for (const out of outputs) {
    const pid = out.paymentId ? `, pid=${out.paymentId}` : "";
    log(`    ${formatAmount(out.amount)}${out.isChange ? " (change)" : ""}${pid}, c=${out.commitmentHex}`);
  }
  log(`  Fee: ${formatAmount(fee)}`);
  ok(`built: ${builtTx.toBytes().length} bytes`);

  // Prove (WARNING: ~16GB RAM, several minutes)
  log("\n  Proving transaction (this takes several minutes)...");
  const start = Date.now();
  const provenTx = builtTx.prove();
  ok(`proven in ${((Date.now() - start) / 1000).toFixed(1)}s`);

  if (provenTx.hasProofCollection()) ok("has ProofCollection");

  // Submit
  log("\n  Submitting transaction...");
  try {
    provenTx.submit(client);
    ok("submitted");
  } catch (e) {
    log(`  submit: ${e}`);
  }

  return true;
}


function testFull(): boolean {
  log("=== XNT-SDK TypeScript Test ===\n");

  const tests = [testVersion, testSeed, testAddress, testUtils, testRpc, testSync];
  let passed = 0;

  for (const test of tests) {
    if (test()) passed++;
    log();
  }

  log(`=== Done: ${passed}/${tests.length} passed ===`);
  return passed === tests.length;
}

const cmd = process.argv[2] || "full";
const testMap: Record<string, () => boolean> = {
  version: testVersion, seed: testSeed, address: testAddress,
  rpc: testRpc, sync: testSync, utils: testUtils, tx: testTx, full: testFull,
};

if (testMap[cmd]) {
  const success = testMap[cmd]();
  if (cmd === "full") process.exit(success ? 0 : 1);
} else {
  console.error(`Unknown: ${cmd}`);
  process.exit(1);
}
