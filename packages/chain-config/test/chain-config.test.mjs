import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import {
  chainId, contracts, aaStack, precompiles, memberSBT, membershipVault,
  flatten, getAddress, checkDrift, raw,
} from '../src/index.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const embedded = JSON.parse(readFileSync(resolve(here, '../src/addresses.40204.json'), 'utf8'))

test('exports match the embedded canonical snapshot', () => {
  assert.equal(chainId, 40204)
  assert.deepEqual(contracts, embedded.contracts)
  assert.deepEqual(aaStack, embedded.aaStack)
  assert.deepEqual(precompiles, embedded.precompiles)
  assert.equal(memberSBT, embedded.CitrateMemberSBT)
  assert.equal(membershipVault, embedded.MembershipStakeVault)
})

test('flatten covers contracts + aaStack + precompiles + the two singletons, collision-free', () => {
  const flat = flatten()
  const n = Object.keys(embedded.contracts).length + Object.keys(embedded.aaStack).length +
    Object.keys(embedded.precompiles).length + 2
  assert.equal(Object.keys(flat).length, n)
  assert.equal(flat.EntryPoint, embedded.aaStack.EntryPoint)
  assert.equal(flat.CitrateMemberSBT, embedded.CitrateMemberSBT)
})

test('getAddress resolves and throws on unknown', () => {
  assert.equal(getAddress('X402Facilitator'), embedded.contracts.X402Facilitator)
  assert.throws(() => getAddress('NoSuchContract'), /unknown contract/)
})

test('checkDrift passes on an identical book', () => {
  assert.equal(checkDrift(raw).ok, true)
  assert.equal(checkDrift(flatten()).ok, true)
})

test('checkDrift flags a mutated address', () => {
  const bad = flatten()
  bad.X402Facilitator = '0xdeadbeef00000000000000000000000000000000'
  const r = checkDrift(bad)
  assert.equal(r.ok, false)
  assert.equal(r.mismatched.length, 1)
  assert.equal(r.mismatched[0].name, 'X402Facilitator')
})

test('checkDrift flags a missing address', () => {
  const partial = flatten()
  delete partial.CitrateMemberSBT
  const r = checkDrift(partial)
  assert.equal(r.ok, false)
  assert.ok(r.missing.includes('CitrateMemberSBT'))
})

test('checkDrift is checksum/case-insensitive', () => {
  const flat = flatten()
  const upper = Object.fromEntries(Object.entries(flat).map(([k, v]) => [k, v.toUpperCase().replace('0X', '0x')]))
  assert.equal(checkDrift(upper).ok, true)
})
