#!/usr/bin/env node
// Drift gate for consumer repos. Compares a repo's vendored address file against
// canonical @citratelabs/chain-config. Exit 1 on drift so CI fails loudly
// after a re-roll instead of shipping dead addresses.
//
//   citrate-chain-config check <path-to-vendored-json> [--canonical <path>]
//
// <path> may be a 40204.json-shaped file, an { "contracts": {...} } file, or a
// flat { "Name": "0x..." } map. With --canonical, compare against that file
// (e.g. the sibling citrate-chain/contracts/addresses/40204.json in an on-disk
// federation checkout) instead of the package's embedded snapshot.
import { readFileSync } from 'node:fs'
import { checkDrift, flatten } from '../src/index.mjs'

const argv = process.argv.slice(2)
const cmd = argv[0]
if (cmd !== 'check') {
  console.error('usage: citrate-chain-config check <path-to-vendored-json> [--canonical <path>]')
  process.exit(2)
}
const target = argv[1]
if (!target) { console.error('error: missing <path-to-vendored-json>'); process.exit(2) }

const ci = argv.indexOf('--canonical')
const canonicalPath = ci !== -1 ? argv[ci + 1] : null

let candidate
try { candidate = JSON.parse(readFileSync(target, 'utf8')) }
catch (e) { console.error(`error: cannot read/parse ${target}: ${e.message}`); process.exit(2) }

let result
if (canonicalPath) {
  const canon = JSON.parse(readFileSync(canonicalPath, 'utf8'))
  const expected = flatten(canon)
  const actual = candidate.contracts || candidate.aaStack ? flatten(candidate) : candidate
  const norm = (a) => (typeof a === 'string' ? a.toLowerCase() : a)
  const missing = [], mismatched = []
  for (const [n, a] of Object.entries(expected)) {
    if (!(n in actual)) missing.push(n)
    else if (norm(actual[n]) !== norm(a)) mismatched.push({ name: n, expected: a, actual: actual[n] })
  }
  result = { ok: !missing.length && !mismatched.length, missing, mismatched, extra: [] }
} else {
  result = checkDrift(candidate)
}

if (result.ok) {
  console.log(`[chain-config] ${target} matches canonical ✓`)
  process.exit(0)
}
console.error(`[chain-config] DRIFT in ${target}:`)
if (result.missing.length) console.error(`  missing (${result.missing.length}): ${result.missing.join(', ')}`)
for (const m of result.mismatched) console.error(`  mismatch ${m.name}: vendored ${m.actual} != canonical ${m.expected}`)
console.error('\n[chain-config] re-sync this repo from canonical 40204.json before merging.')
process.exit(1)
