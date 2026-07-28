#!/usr/bin/env node
// Refresh the package's embedded snapshot from the canonical source of truth,
// citrate-chain/contracts/addresses/40204.json. This is the ONLY thing that
// should ever write src/addresses.40204.json — never hand-edit it.
//
//   node scripts/generate.mjs           # regenerate the embedded snapshot
//   node scripts/generate.mjs --check   # exit 1 if the embedded snapshot has
//                                       # drifted from canonical (CI gate)
//
// Run (or --check) this in citrate-chain CI after every re-roll so the
// published @citratenetwork/chain-config can never lag the on-chain book.
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const CANONICAL = resolve(here, '../../../contracts/addresses/40204.json')
const EMBEDDED = resolve(here, '../src/addresses.40204.json')

const check = process.argv.includes('--check')

let canonical
try {
  canonical = readFileSync(CANONICAL, 'utf8')
} catch {
  console.error(`[chain-config] canonical source not found at ${CANONICAL}`)
  console.error('[chain-config] run this from within the citrate-chain repo (it reads the sibling 40204.json).')
  process.exit(1)
}
// normalize (parse+stringify) so formatting never causes a false drift
const normalized = JSON.stringify(JSON.parse(canonical), null, 2) + '\n'

if (check) {
  let embedded = ''
  try { embedded = readFileSync(EMBEDDED, 'utf8') } catch {}
  if (embedded !== normalized) {
    console.error('[chain-config] DRIFT: embedded snapshot is stale vs canonical 40204.json.')
    console.error('[chain-config] run `node scripts/generate.mjs` and commit the result.')
    process.exit(1)
  }
  console.log('[chain-config] embedded snapshot matches canonical 40204.json ✓')
  process.exit(0)
}

writeFileSync(EMBEDDED, normalized)
console.log(`[chain-config] regenerated ${EMBEDDED} from canonical 40204.json`)
