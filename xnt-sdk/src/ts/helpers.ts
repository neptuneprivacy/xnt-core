import {
  XntTransactionBuilder,
  XntMembershipProof,
  XntPendingUtxo,
  xntGetMembershipProofs,
} from "../napi/output";

/**
 * Selected input for mixed Generation + CTIDH transactions.
 */
export type MixedSelectedInput = {
  kind: "gen" | "ctidh";
  u: XntPendingUtxo;
};

export type IndexedSelected = {
  s: MixedSelectedInput;
  idx: number;
};

/**
 * Add heterogeneous inputs (Generation + CTIDH) to a `XntTransactionBuilder`
 * using the correct membership proof for each key type.
 */
export function addMultiTypeInputs(
  builder: XntTransactionBuilder,
  selected: MixedSelectedInput[],
  genKey: any,
  ctidhKey: any,
  genProofBuffers: Buffer[],
  ctidhProofBuffers: Buffer[],
  genSelected: IndexedSelected[],
  ctidhSelected: IndexedSelected[],
): void {
  for (let i = 0; i < selected.length; i++) {
    const item = selected[i];

    if (item.kind === "gen") {
      const pos = genSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(genProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, genKey, proof);
    } else {
      const pos = ctidhSelected.findIndex(x => x.idx === i);
      if (pos < 0) continue;
      const proof = XntMembershipProof.fromBytes(ctidhProofBuffers[pos]);
      builder.addInput(item.u.decrypted.utxo, ctidhKey, proof);
    }
  }
}

/**
 * Build membership proofs for a mixed set of selected inputs (Generation + CTIDH).
 *
 * Returns the partitioned selections plus the raw proof buffers so callers can
 * log counts or inspect them before adding inputs to a transaction.
 */
export function buildMixedProofs(
  client: any,
  genKey: any,
  ctidhKey: any,
  selected: MixedSelectedInput[],
): {
  genSelected: IndexedSelected[];
  ctidhSelected: IndexedSelected[];
  genProofBuffers: Buffer[];
  ctidhProofBuffers: Buffer[];
} {
  const genSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "gen");
  const ctidhSelected: IndexedSelected[] = selected
    .map((s, idx) => ({ s, idx }))
    .filter(x => x.s.kind === "ctidh");

  const genProofBuffers: Buffer[] = genSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        genSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        genSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        genKey.receiverPreimageHex(),
        genSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  const ctidhProofBuffers: Buffer[] = ctidhSelected.length > 0
    ? xntGetMembershipProofs(
        client,
        ctidhSelected.map(x => x.s.u.decrypted.utxo.hashHex()),
        ctidhSelected.map(x => x.s.u.decrypted.senderRandomnessHex),
        ctidhKey.receiverPreimageHex(),
        ctidhSelected.map(x => x.s.u.aoclIndex),
      )
    : [];

  return { genSelected, ctidhSelected, genProofBuffers, ctidhProofBuffers };
}

