# Active Mocks — Must Be Replaced

**Mock budget: 0 for new code. This file tracks existing debt being eliminated.**

When this file is empty, delete it. Zero mocks = no file needed.

**Background:** See `.agentile/docs/case_studies/MOCK_PERSISTENCE.md` for why this registry exists.

---

| # | IPC Command | Current Behavior | Target Contract | Replacement Sprint |
|---|-------------|-----------------|----------------|-------------------|
| 1 | `learning_get_pools` | 3 hardcoded pools | LearningPool.getPool() | CLEANUP |
| 2 | `learning_join_pool` | Log + Ok(true) | LearningPool.joinPool() tx | CLEANUP |
| 3 | `learning_leave_pool` | Log + Ok(true) | LearningPool.leavePool() tx | CLEANUP |
| 4 | `learning_create_pool` | Log + Ok(0) | LearningPool.createPool() tx | CLEANUP |
| 5 | `learning_get_classroom` | Hardcoded classroom | ClassroomRegistry views | CLEANUP |
| 6 | `learning_create_classroom` | Log + Ok(true) | ClassroomRegistry.createClassroom() tx | CLEANUP |
| 7 | `learning_get_students` | 3 fake students | ClassroomRegistry views | CLEANUP |
| 8 | `learning_generate_invite_code` | Random hex string | ClassroomRegistry.rotateInviteCode() tx | CLEANUP |
| 9 | `learning_join_classroom` | Log + Ok(true) | ClassroomRegistry.enrollWithCode() tx | CLEANUP |
| 10 | `learning_add_whitelisted_model` | Log + Ok(true) | ClassroomRegistry.whitelistModel() tx | CLEANUP |
| 11 | `learning_remove_whitelisted_model` | Log + Ok(true) | ClassroomRegistry.removeModel() tx | CLEANUP |
| 12 | `learning_get_cycle_status` | Static OODA phase | LearningCycleManager views | CLEANUP |
| 13 | `learning_get_earnings` | Hardcoded SALT amounts | ContributionAccounting.getScore() | CLEANUP |
| 14 | `learning_get_model_catalog` | 6 seed models | ModelRegistry.getModel() | CLEANUP |
| 15 | `learning_start_training` | Fake job ID | LoRAFactory.createAdapter() tx | CLEANUP |

**Total: 15 mocks. Target: 0.**

## Cleanup Plan

See `.agentile/docs/journals/2026-03-22_LC3_COMPLETE.md` for the 5-phase replacement plan:

1. **Contract Query Infrastructure** — Build reusable `ContractCaller` in Tauri backend
2. **Wire Read Commands** — Replace all `eth_call` mocks (6 commands)
3. **Wire Write Commands** — Replace all transaction mocks (9 commands)
4. **Integration Tests** — Deploy contract + call IPC + verify data for each command
5. **Compile Gate** — `#[cfg(not(feature = "allow-mocks"))]` blocks release builds
