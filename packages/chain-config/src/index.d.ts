export type Address = string
export type AddressMap = Record<string, Address>

export const chainId: number
export const chainName: string
export const rpcUrl: string
export const explorerUrl: string
export const deployer: Address
export const deployedAt: string

export const contracts: AddressMap
export const aaStack: AddressMap
export const precompiles: AddressMap
/** nonce-based, MOVES every re-roll — always getCode-verify at boot */
export const memberSBT: Address
/** nonce-based, MOVES every re-roll — always getCode-verify at boot */
export const membershipVault: Address

export interface AddressBook {
  chainId: number
  chainName: string
  rpcUrl: string
  explorerUrl: string
  deployer: Address
  deployedAt: string
  contracts: AddressMap
  aaStack: AddressMap
  precompiles: AddressMap
  CitrateMemberSBT?: Address
  MembershipStakeVault?: Address
  [k: string]: unknown
}

export const raw: AddressBook

export function flatten(src?: AddressBook): AddressMap
export function getAddress(name: string): Address

export interface DriftResult {
  ok: boolean
  missing: string[]
  mismatched: Array<{ name: string; expected: Address; actual: Address }>
  extra: string[]
}

/** Compare a candidate address set against canonical (case-insensitive). */
export function checkDrift(candidate: Partial<AddressBook> | AddressMap): DriftResult
