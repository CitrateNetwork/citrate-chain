---
created: 2026-04-07T21:30:00Z
branch: benchmark-rehearsal
author: Codex (OpenAI, GPT-5)
status: active
scope: Guided operator flow for the real 40204 ceremony
---

# Guided Operator Flow

## What This Is

This is the simplest safe way to run the ceremony without sharing keys in chat
or memorizing a long list of environment variables.

The operator-facing entrypoint is:

```bash
./citrate_v0.01.1/scripts/ceremony/guided_ceremony.sh
```

That wrapper:

- prompts you in the terminal for the values the ceremony needs
- lets you use an existing Foundry keystore account, create a fresh one, or
  import an existing EVM private key interactively
- derives the deployer address locally on your machine
- writes a temporary env file with public values only
- optionally launches `ceremony.sh` for you

It does **not** ask you to paste private keys into chat.

## Keep These Worlds Separate

- `rehearsal`:
  local or disposable practice only
- `real`:
  the actual shared testnet ceremony on chain ID `40204`

The wrapper asks which one you mean so we do not conflate devnet rehearsal with
the real testnet.

## What The Wrapper Can Do For You

### 1. Deployer keystore setup

You choose one of three paths:

- use an existing Foundry keystore account
- create a fresh Foundry keystore account now
- import an existing EVM private key interactively

If you create or import a key, the prompt happens locally in your terminal.

### 2. Collect the ceremony inputs

The wrapper asks for:

- RPC URL
- vault signer addresses
- governance address
- relayer address
- contract scope (`35` or `36`)
- optional genesis file path
- optional SALT/USD rate override

### 3. Hand off to the real ceremony runner

Once the values are collected, the wrapper can run:

```bash
./citrate_v0.01.1/scripts/ceremony/ceremony.sh
```

with the correct environment already set.

## What The Wrapper Cannot Invent

The wrapper can simplify the mechanics, but it cannot make governance decisions
for you.

You still need to decide and provide:

- the real operator-controlled signer addresses
- the real deployer account you want to trust for the ceremony
- the real RPC endpoint
- whether the scope is `35` or `36` contracts
- how the deployer and later benchmark signers will be funded

## Phantom Wallet Note

If you have an EVM-compatible private key from Phantom and want to use it:

1. choose `import an existing EVM private key` in the wrapper
2. let `cast wallet import --interactive` ask for the key locally
3. do not paste the key into chat

That keeps the secret on your machine while still putting it into the Foundry
keystore flow that `ceremony.sh` expects.

## Bit-By-Bit Flow

### Step 1. Run the wrapper

```bash
./citrate_v0.01.1/scripts/ceremony/guided_ceremony.sh
```

### Step 2. Pick the mode

- choose `real` only for the actual `40204` ceremony
- choose `rehearsal` for disposable practice

### Step 3. Pick the deployer account flow

- existing keystore account
- create fresh keystore account
- import an existing private key interactively

### Step 4. Confirm the derived deployer address

The wrapper derives the public address locally and shows it back to you before
continuing.

### Step 5. Enter the public ceremony values

You will be prompted for:

- `SIGNER_1`
- `SIGNER_2`
- `SIGNER_3`
- `GOVERNANCE`
- `RELAYER`
- `CEREMONY_RPC_URL`
- contract scope

### Step 6. Review the summary

The wrapper prints a summary before running anything.

### Step 7. Let it launch `ceremony.sh`

If you answer `yes`, the wrapper exports the environment and runs the actual
ceremony runner.

If you answer `no`, it leaves you with a temp env file and prints the exact
command to run later.

## What Gets Written To Disk

The wrapper writes a temporary env file under `/tmp`, for example:

```text
/tmp/citrate-ceremony-env.20260407T213000Z.sh
```

That file contains:

- public addresses
- account name
- RPC URL
- chain ID
- contract-scope flag

It does **not** contain:

- private keys
- passphrases

## Real Ceremony Recommendation

For the real `40204` run:

- use a fresh deployer key or a clearly designated ceremony deployer key
- use real signer addresses, not rehearsal placeholders
- use a real benchmark sink address that you control and that is not a
  precompile
- keep `36` contracts as the default unless you have an explicit reason to
  exclude `ModelAccessControl`

## Exact Command To Start

```bash
./citrate_v0.01.1/scripts/ceremony/guided_ceremony.sh
```

If you choose not to auto-run, the wrapper will print the exact `source ... &&
./ceremony.sh` command for you.

## What To Hand Me Next

After you run it, the useful outputs are:

- the deployer address it derived
- the public signer / governance / relayer addresses you entered
- whether you chose `35` or `36`
- the output directory from `ceremony.sh`

You still do not need to share private keys.
