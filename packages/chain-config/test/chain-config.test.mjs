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
  // every name from every section is present exactly once
  const names = new Set([
    ...Object.keys(embedded.contracts), ...Object.keys(embedded.aaStack),
    ...Object.keys(embedded.precompiles), 'CitrateMemberSBT', 'MembershipStakeVault',
  ])
  assert.equal(Object.keys(flat).length, names.size)
  // a name that appears in more than one section must agree on the address
  const sections = [embedded.contracts, embedded.aaStack, embedded.precompiles,
    { CitrateMemberSBT: embedded.CitrateMemberSBT, MembershipStakeVault: embedded.MembershipStakeVault }]
  for (const name of names) {
    const addrs = new Set(sections.filter((s) => name in s).map((s) => s[name].toLowerCase()))
    assert.equal(addrs.size, 1, `${name} resolves to ${addrs.size} distinct addresses`)
    assert.equal(flat[name].toLowerCase(), [...addrs][0])
  }
  assert.equal(flat.EntryPoint, embedded.aaStack.EntryPoint)
  assert.equal(flat.CitrateMemberSBT, embedded.CitrateMemberSBT)
})

test('flatten throws when one name maps to two different addresses', () => {
  const corrupt = {
    contracts: { CitrateMemberSBT: '0x1111111111111111111111111111111111111111' },
    CitrateMemberSBT: '0x2222222222222222222222222222222222222222',
  }
  assert.throws(() => flatten(corrupt), /conflicting addresses for CitrateMemberSBT/)
  const crossSection = {
    contracts: { EntryPoint: '0x1111111111111111111111111111111111111111' },
    aaStack: { EntryPoint: '0x2222222222222222222222222222222222222222' },
  }
  assert.throws(() => flatten(crossSection), /conflicting addresses for EntryPoint/)
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

// --- CLI --subset mode (for repos that pin an intentional slice, e.g. radar) ---
import { execFileSync } from 'node:child_process'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'

const CLI = resolve(here, '../bin/check.mjs')
const tmp = mkdtempSync(resolve(tmpdir(), 'cc-subset-'))
const runCli = (args) => {
  try { execFileSync('node', [CLI, ...args], { stdio: 'pipe' }); return 0 }
  catch (e) { return e.status ?? 1 }
}

test('CLI --subset passes a partial book whose pinned addresses all match', () => {
  const flat = flatten()
  const partial = { X402Facilitator: flat.X402Facilitator, EntryPoint: flat.EntryPoint }
  const p = resolve(tmp, 'partial-ok.json'); writeFileSync(p, JSON.stringify(partial))
  assert.equal(runCli(['check', p, '--subset']), 0)
  // without --subset the same partial file fails (missing the rest of the book)
  assert.equal(runCli(['check', p]), 1)
})

test('CLI --subset still fails on a mismatched pinned address', () => {
  const bad = { X402Facilitator: '0xdeadbeef00000000000000000000000000000000' }
  const p = resolve(tmp, 'partial-bad.json'); writeFileSync(p, JSON.stringify(bad))
  assert.equal(runCli(['check', p, '--subset']), 1)
})
