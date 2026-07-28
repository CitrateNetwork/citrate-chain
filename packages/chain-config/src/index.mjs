// @citratenetwork/chain-config — canonical Citrate 40204 config.
// Import these instead of vendoring raw addresses. Regenerated from
// citrate-chain/contracts/addresses/40204.json (see scripts/generate.mjs).
import book from './addresses.40204.json' with { type: 'json' }

export const chainId = book.chainId
export const chainName = book.chainName
export const rpcUrl = book.rpcUrl
export const explorerUrl = book.explorerUrl
export const deployer = book.deployer
export const deployedAt = book.deployedAt

/** name -> address, the 53 core contracts */
export const contracts = book.contracts
/** ERC-4337 stack (EntryPoint, CitrateWallet, factory, paymaster, validators, guardian) */
export const aaStack = book.aaStack
/** model/tensor precompiles at 0x…0100+ */
export const precompiles = book.precompiles
/** nonce-based, MOVES every re-roll — always getCode-verify at boot */
export const memberSBT = book.CitrateMemberSBT
/** nonce-based, MOVES every re-roll — always getCode-verify at boot */
export const membershipVault = book.MembershipStakeVault

/** the whole canonical book, if you need something not surfaced above */
export const raw = book

const norm = (a) => (typeof a === 'string' ? a.toLowerCase() : a)

/**
 * Flatten the canonical book to a single name->address map (contracts + aaStack
 * + precompiles + the two nonce-based singletons). Names collide-free by design.
 */
export function flatten(src = book) {
  const out = {}
  for (const [k, v] of Object.entries(src.contracts || {})) out[k] = v
  for (const [k, v] of Object.entries(src.aaStack || {})) out[k] = v
  for (const [k, v] of Object.entries(src.precompiles || {})) out[k] = v
  if (src.CitrateMemberSBT) out.CitrateMemberSBT = src.CitrateMemberSBT
  if (src.MembershipStakeVault) out.MembershipStakeVault = src.MembershipStakeVault
  return out
}

/** Look up one address by name across all sections. Throws if unknown. */
export function getAddress(name) {
  const flat = flatten()
  if (!(name in flat)) throw new Error(`[chain-config] unknown contract: ${name}`)
  return flat[name]
}

/**
 * Compare a candidate address set against canonical. Accepts either a parsed
 * 40204.json-shaped object, an { contracts: {...} } object, or a flat
 * name->address map. Address comparison is case-insensitive (checksum-agnostic).
 * @returns {{ ok: boolean, missing: string[], mismatched: Array<{name,expected,actual}>, extra: string[] }}
 */
export function checkDrift(candidate) {
  const expected = flatten()
  let actual
  if (candidate && (candidate.contracts || candidate.aaStack)) actual = flatten(candidate)
  else actual = candidate || {}

  const missing = []
  const mismatched = []
  for (const [name, addr] of Object.entries(expected)) {
    if (!(name in actual)) { missing.push(name); continue }
    if (norm(actual[name]) !== norm(addr)) mismatched.push({ name, expected: addr, actual: actual[name] })
  }
  const extra = Object.keys(actual).filter((n) => !(n in expected))
  return { ok: missing.length === 0 && mismatched.length === 0, missing, mismatched, extra }
}
