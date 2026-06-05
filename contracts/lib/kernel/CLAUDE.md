# Development Guidelines

## Build Commands
- `forge build` - Compile all contracts
- `forge test` - Run all tests
- `forge test --match-test testFunctionName` - Run a single test
- `forge test --match-path test/Kernel.t.sol` - Run tests in a specific file
- `forge test -vv` - Run tests with verbose output
- `FOUNDRY_PROFILE=optimized forge test` - Run tests with optimized profile

## Code Style

### Formatting
- Indentation: 4 spaces
- Opening braces: same line as declaration
- Use named imports: `import {Contract} from "./path.sol";`
- Line separators: `// --- Section Name ---`

### Naming Conventions
- Contracts: PascalCase (e.g. `Kernel`)
- Interfaces: Prefixed with "I" (e.g. `IValidator`)
- Functions: camelCase (e.g. `validateUserOp`)
- Private/internal: underscore prefix (e.g. `_executeUserOp`)
- Constants: ALL_CAPS_WITH_UNDERSCORES

### Error Handling
- Use custom errors instead of require (e.g. `error InvalidValidator();`)
- Use if-revert pattern: `if (condition) { revert ErrorName(); }`

### Types and Structure
- Use immutable variables when possible for gas optimization
- Follow ERC-4337 and ERC-7579 standards
- Use explicit storage slots with assembly for upgradeability