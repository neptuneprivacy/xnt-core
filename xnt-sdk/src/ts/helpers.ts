import {
  XntTransactionBuilder,
  XntMembershipProof,
  XntDecryptedUtxo,
  xntGetMembershipProofs,
} from "../napi/output";

/**
 * An unspent UTXO with its decrypted data and AOCL index.
 */
export type UnspentUtxo = {
  decrypted: XntDecryptedUtxo;
  aoclIndex: number;
};

/**
 * Selected input for mixed Generation + dCTIDH transactions.
 */
export type MixedSelectedInput = {
  kind: "gen" | "dctidh";
  u: UnspentUtxo;
};

export type IndexedSelected = {
  s: MixedSelectedInput;
  idx: number;
};

/**
 * Add heterogeneous inputs (Generation + dCTIDH) to a `XntTransactionBuilder`
 * using the correct membership proof for each key type.
 */
export function addMultiTypeInputs(
  builder: XntTransactionBuilder,
  selected: MixedSelectedInput[],
  genKey: any,
  dCTIDHKey: any,
  genProofBuffers: Buffer[],
  dCTIDHProofBuffers: Buffer[],
  genSelected: IndexedSelected[],
  dCTIDHSelected: IndexedSelected[],
): void {
  for (let i = 0; i < selected.length; i++) {
    const item = selected[i];

    if (item.kind === "gen") {
      const pos = genSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(genProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, genKey, proof);
    } else {
      const pos = dCTIDHSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(dCTIDHProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, dCTIDHKey, proof);
    }
  }
}

/**
 * Build membership proofs for a mixed set of selected inputs (Generation + dCTIDH).
 *
 * Returns the partitioned selections plus the raw proof buffers so callers can
 * log counts or inspect them before adding inputs to a transaction.
 */
export function buildMixedProofs(
  client: any,
  genKey: any,
  dCTIDHKey: any,
  selected: MixedSelectedInput[],
): {
  genSelected: IndexedSelected[];
  dCTIDHSelected: IndexedSelected[];
  genProofBuffers: Buffer[];
  dCTIDHProofBuffers: Buffer[];
} {
  const genSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "gen");
  const dCTIDHSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "dctidh");

  const genProofBuffers: Buffer[] = genSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        genSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        genSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        genKey.receiverPreimageHex(),
        genSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  const dCTIDHProofBuffers: Buffer[] = dCTIDHSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        dCTIDHSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        dCTIDHSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        dCTIDHKey.receiverPreimageHex(),
        dCTIDHSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  return { genSelected, dCTIDHSelected, genProofBuffers, dCTIDHProofBuffers };
}

