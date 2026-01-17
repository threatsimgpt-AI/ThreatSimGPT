# ThreatSimGPT Commit Attribution Document

> **Last Updated:** January 17, 2026  
> **Repository:** threatsimgpt-AI/ThreatSimGPT  
> **Purpose:** Comprehensive tracking of all contributions to the codebase

---

## Table of Contents

1. [Maintainer Registry](#maintainer-registry)
2. [Merged Pull Requests](#merged-pull-requests)
3. [Individual Commit Attributions](#individual-commit-attributions)
4. [Collaborative Contributions](#collaborative-contributions)
5. [Squashed Commits Attribution](#squashed-commits-attribution)
6. [Contribution Timeline](#contribution-timeline)

---

## Maintainer Registry

| GitHub Username | Full Name | Email | Primary Contributions |
|-----------------|-----------|-------|----------------------|
| `@Thundastormgod` | Thundastormgod | threatsimgpt@hotmail.com | Project Lead, Event Sourcing, Safety Guardrails |
| `@jiboo2022` | AJIBOLA OLAJIDE-SHOKUNBI | jiboo2022@users.noreply.github.com | CI/CD, API Development, Security Fixes |
| `@bayulus` | Olabisi Olajide | 77527597+bayulus@users.noreply.github.com | Template Security, Guardrails Engineering |
| `@ocheme1107` | David Onoja | onojad@gmail.com | SIEM Detection Rules, SPL Injection Fix |
| `@TemiAdebola` | Temi Adebola | noblenabeela360@gmail.com | ContentFilter, Event Sourcing |
| `@Shizoqua` | Lanre Shittu | 136805224+Shizoqua@users.noreply.github.com | Safety Guardrails Engine |
| `@laradipupo` | Laradev | omolaradipupo11@gmail.com | Docker Containerization |
| `@mykael02` | Mykael | apochibishop@gmail.com | Testing Infrastructure |
| `@2abet` | Akinyemi Arabambi | 32962207+2abet@users.noreply.github.com | Documentation Fixes |
| `@threatsimgpt-AI` | ThreatSimGPT (Org) | threatsimgpt@gmail.com | Merge Operations, Maintenance |

---

## Merged Pull Requests

### PR #92 - CI Security Fix + Template Security Validation
**Merged:** January 17, 2026  
**Author:** @jiboo2022 (AJIBOLA OLAJIDE-SHOKUNBI)  
**Merged By:** @threatsimgpt-AI  
**Squash Commit:** `db320f7`

| Included Work | Original Author | Original Commits |
|---------------|-----------------|------------------|
| Template Security Validator (74 tests) | @bayulus (Olabisi Olajide) | `9a48d51`, `bcfc37a` |
| CI Workflow Fixes | @jiboo2022 | `f9e5455`, `193443a`, `5d9a1fc`, `d0911d6` |
| Dependency Conflict Resolution | @jiboo2022 | `cccf7eb`, `7c54c11` |
| Pydantic ConfigDict Migration | @jiboo2022 | `8bfdc5f` |
| Datetime Deprecation Fix | @jiboo2022 | `094da8e` |
| Bandit B110 Fix | @jiboo2022 | `e049887`, `d62359d` |
| pytest-asyncio Addition | @jiboo2022 | `748e4b7` |
| Requirements.txt Install Fix | @jiboo2022 | `48a937d` |

**Issues Closed:** #74, #75, #76, #77, #85, #83, #84, #17, #2

---

### PR #73 - REST API for Feedback Loop
**Merged:** January 17, 2026  
**Author:** @jiboo2022 (AJIBOLA OLAJIDE-SHOKUNBI)  
**Merged By:** @threatsimgpt-AI  
**Squash Commit:** `60fe85c`

| Component | Description |
|-----------|-------------|
| 7 REST Endpoints | Feedback submission, metrics, analysis, learnings |
| Security Features | Input sanitization, path traversal protection |
| Pydantic Validation | Request/response models |

**Issues Closed:** #3

---

### PR #69 - Safety Guardrails Engine
**Merged:** January 15, 2026  
**Author:** @Thundastormgod  
**Merged By:** @threatsimgpt-AI  
**Merge Commits:** `3b89145`, `e82b519`

| Included Work | Original Author | Original Commits |
|---------------|-----------------|------------------|
| RateLimiter & CircuitBreaker Fixes | @bayulus (Olabisi Olajide) | `05d8f1e`, `30c2ad7`, `397a160` |
| P0 Security Fixes for Guardrails | @bayulus (Olabisi Olajide) | `e8bb1c1`, `9fc744c`, `7dee4f2` |
| Safety Guardrails Implementation | @Shizoqua (Lanre Shittu) | `2fb091b`, `5ba783f` |

---

### PR #61 - Event Sourcing Foundation (Phase 1)
**Merged:** January 14, 2026  
**Author:** @Thundastormgod  
**Merged By:** @Thundastormgod  
**Merge Commit:** `761a02a`

| Included Work | Original Author | Original Commits |
|---------------|-----------------|------------------|
| Event Sourcing Foundation | @TemiAdebola (Temi Adebola) | `e725f7d` |

---

### PR #60 - ContentFilter with Kill Switch
**Merged:** January 14, 2026  
**Author:** @TemiAdebola (Temi Adebola)  
**Merged By:** @Thundastormgod  
**Commit:** `86444c1`

---

### PR #59 - SPL Injection Prevention
**Merged:** January 4, 2026  
**Author:** @ocheme1107 (David Onoja)  
**Merged By:** @threatsimgpt-AI  
**Squash Commit:** `680478f`

| Included Work | Original Author | Original Commits |
|---------------|-----------------|------------------|
| SPL Injection Prevention | @ocheme1107 (David Onoja) | `1505301`, `2d75b45` |
| Code Quality Improvements | @jiboo2022 | `8f01b56` |

---

### PR #57 - SIEM Detection Rule Generator
**Merged:** January 4, 2026  
**Author:** @ocheme1107 (David Onoja)  
**Merged By:** @ocheme1107  
**Commit:** `12e7b7f`

---

## Individual Commit Attributions

### January 2026

| Date | Commit | Author | Description |
|------|--------|--------|-------------|
| 2026-01-17 | `60fe85c` | @jiboo2022 | feat(api): REST API for feedback loop (squash merge) |
| 2026-01-17 | `db320f7` | @jiboo2022 | fix(security): Bandit B110 + template security (squash merge) |
| 2026-01-17 | `094da8e` | @jiboo2022 | fix: datetime.utcnow() deprecation |
| 2026-01-17 | `8bfdc5f` | @jiboo2022 | fix: Pydantic ConfigDict migration |
| 2026-01-17 | `7c54c11` | @jiboo2022 | fix: dev dependency conflicts |
| 2026-01-17 | `cccf7eb` | @jiboo2022 | fix: anyio version conflict (FastAPI/MCP) |
| 2026-01-17 | `48a937d` | @jiboo2022 | fix(ci): requirements.txt install |
| 2026-01-17 | `748e4b7` | @jiboo2022 | fix(ci): pytest-asyncio dependency |
| 2026-01-17 | `f9e5455` | @jiboo2022 | fix(ci): Replace deprecated linters with ruff |
| 2026-01-17 | `193443a` | @jiboo2022 | fix(ci): upgrade actions v3 to v4 |
| 2026-01-17 | `5d9a1fc` | @jiboo2022 | fix(ci): add master branch to triggers |
| 2026-01-17 | `d0911d6` | @jiboo2022 | fix(ci): ruff and bandit config |
| 2026-01-17 | `e4978d6` | @jiboo2022 | fix(deps): add ruff, remove deprecated tools |
| 2026-01-16 | `e049887` | @jiboo2022 | fix(security): Bandit B110 try-except-pass |
| 2026-01-16 | `9a48d51` | @bayulus | feat(security): Template security validation (Issue #74) |
| 2026-01-16 | `bcfc37a` | @bayulus | feat(security): Template security validation (Issue #74) |
| 2026-01-16 | `58886a6` | @jiboo2022 | feat(api): REST API for feedback loop (#3) |
| 2026-01-15 | `3b89145` | @threatsimgpt-AI | Merge PR #69 (Safety Guardrails) |
| 2026-01-15 | `05d8f1e` | @bayulus | refactor(guardrails): RateLimiter/CircuitBreaker fixes |
| 2026-01-15 | `e8bb1c1` | @bayulus | feat(security): P0 guardrails security fixes |
| 2026-01-14 | `761a02a` | @Thundastormgod | Merge Phase 1 Event Sourcing |
| 2026-01-14 | `2fb091b` | @Shizoqua | feat: safety guardrails engine |
| 2026-01-13 | `e725f7d` | @TemiAdebola | feat(core): Event Sourcing foundation |
| 2026-01-13 | `86444c1` | @TemiAdebola | feat(safety): ContentFilter with kill switch |
| 2026-01-07 | `2232535` | @laradipupo | feat(docker): Docker containerization (Issue #9) |
| 2026-01-04 | `680478f` | @ocheme1107 | fix(security): SPL injection prevention (squash) |
| 2026-01-04 | `8f01b56` | @jiboo2022 | refactor(security): Code quality for SPL fix |
| 2026-01-04 | `2d75b45` | @ocheme1107 | fix(security): SPL injection hardening |
| 2026-01-04 | `1505301` | @ocheme1107 | fix(security): SPL injection in SplunkRuleGenerator |
| 2026-01-04 | `34321f5` | @threatsimgpt-AI | chore(security): Clean .gitignore |
| 2026-01-04 | `6a8285c` | @threatsimgpt-AI | fix(analytics): Lazy-load numpy/sklearn |
| 2026-01-03 | `12e7b7f` | @ocheme1107 | feat(detection): SIEM detection rule generator |
| 2026-01-02 | `bbfa71e` | @Thundastormgod | refactor: Update maintainer roles |
| 2026-01-02 | `4b6472a` | @Thundastormgod | chore: CHANGELOG and PR template |
| 2026-01-02 | `f2a157b` | @Thundastormgod | chore: Simplify .gitignore |

### December 2025

| Date | Commit | Author | Description |
|------|--------|--------|-------------|
| 2025-12-31 | `65bcfbc` | Initial Setup | feat(api): Manuals & Knowledge Base APIs |
| 2025-12-30 | `536502f` | Initial Setup | Initial release: ThreatSimGPT v0.1.0 |
| 2025-12-11 | `c984ce7` | @Thundastormgod | Merge PR #2 |
| 2025-12-10 | `7d40b93` | @mykael02 | refactor: Replace mock with real SDK |
| 2025-12-10 | `ada0ae1` | @mykael02 | feat: Testing infrastructure |

### November 2025

| Date | Commit | Author | Description |
|------|--------|--------|-------------|
| 2025-11-24 | `6f646ae` | Initial Setup | merge: simulator-enhancements |
| 2025-11-21 | `f531386` | @Thundastormgod | Delete SETUP_PRIVATE_REPO.md |
| 2025-11-21 | `675366f` | @Thundastormgod | Merge PR #1 from @2abet |
| 2025-11-06 | `17aa2a7` | @Thundastormgod | docs: 6-Tier Prompt Engineering |
| 2025-11-06 | `ec3e4eb` | @Thundastormgod | docs: Ollama local LLM support |
| 2025-11-06 | `d87e05b` | @Thundastormgod | feat: Ollama local LLM integration |
| 2025-11-02 | `451edc8` | @Thundastormgod | feat: Enhanced simulator |

### October-September 2025

| Date | Commit | Author | Description |
|------|--------|--------|-------------|
| 2025-10-20 | `d897b70` | @2abet | Fix GitHub links in support section |
| 2025-09-29 | `999bc07` | @Thundastormgod | refactor: Production deployment cleanup |
| 2025-09-28 | `228460a` | @Thundastormgod | refactor: Cleaner text output |
| 2025-09-28 | `e6ea4ec` | @Thundastormgod | feat: Content storage system |
| 2025-09-27 | `518d8da` | @Thundastormgod | docs: Virtual environment guide |
| 2025-09-27 | `fedabcc` | @Thundastormgod | feat: Template management system |
| 2025-09-26 | `74caf28` | @Thundastormgod | Initial commit: ThreatGPT system |

---

## Collaborative Contributions

### Template Security Validation (Issue #74)
**Final Merge:** PR #92 by @jiboo2022  
**Original Implementation:** @bayulus (Olabisi Olajide)

| Phase | Contributor | Commits | Work Done |
|-------|-------------|---------|-----------|
| Implementation | @bayulus | `9a48d51`, `bcfc37a` | 74 security tests, TemplateSecurityValidator module |
| Integration & CI Fix | @jiboo2022 | Multiple | Merged into fix branch, resolved CI conflicts |

---

### SPL Injection Prevention (PR #59)
**Final Merge:** @ocheme1107  
**Collaborative:** @jiboo2022

| Phase | Contributor | Commits | Work Done |
|-------|-------------|---------|-----------|
| Initial Fix | @ocheme1107 | `1505301` | Basic SPL injection prevention |
| Hardening | @ocheme1107 | `2d75b45` | Comprehensive prevention |
| Code Quality | @jiboo2022 | `8f01b56` | Refactoring and improvements |

---

### Safety Guardrails Engine (PR #69)
**Final Merge:** @Thundastormgod  
**Collaborative:** @bayulus, @Shizoqua

| Phase | Contributor | Commits | Work Done |
|-------|-------------|---------|-----------|
| Core Implementation | @Shizoqua (Lanre Shittu) | `2fb091b` | Guardrails engine with validation |
| P0 Security Fixes | @bayulus | `e8bb1c1` | Critical security patches |
| Engineering Fixes | @bayulus | `05d8f1e` | RateLimiter, CircuitBreaker fixes |

---

## Squashed Commits Attribution

When commits are squash-merged, individual contributions may be hidden. This section preserves attribution.

### PR #92 Squashed Commits → `db320f7`
```
Squash merged 12 commits into 1

Original Authors:
├── @bayulus (Olabisi Olajide)
│   ├── 9a48d51 - Template security validation
│   └── bcfc37a - Template security validation
│
└── @jiboo2022 (AJIBOLA OLAJIDE-SHOKUNBI)
    ├── f9e5455 - CI workflow fixes (ruff migration)
    ├── 193443a - Actions v3 to v4 upgrade
    ├── 5d9a1fc - Master branch triggers
    ├── d0911d6 - Ruff/bandit config
    ├── e4978d6 - Add ruff dependency
    ├── e049887 - Bandit B110 fix
    ├── cccf7eb - anyio version conflict
    ├── 7c54c11 - Dev dependency conflicts
    ├── 8bfdc5f - Pydantic ConfigDict migration
    ├── 094da8e - datetime.utcnow() deprecation
    ├── 748e4b7 - pytest-asyncio addition
    └── 48a937d - requirements.txt install
```

### PR #73 Squashed Commits → `60fe85c`
```
Squash merged 1 commit

Original Author:
└── @jiboo2022 (AJIBOLA OLAJIDE-SHOKUNBI)
    └── 58886a6 - REST API for feedback loop
```

### PR #59 Squashed Commits → `680478f`
```
Squash merged 3 commits into 1

Original Authors:
├── @ocheme1107 (David Onoja)
│   ├── 1505301 - Initial SPL injection fix
│   └── 2d75b45 - Comprehensive hardening
│
└── @jiboo2022 (AJIBOLA OLAJIDE-SHOKUNBI)
    └── 8f01b56 - Code quality improvements
```

---

## Contribution Timeline

```
2025-09-26  ┌─────────────────────────────────────────────────────────────────┐
            │ @Thundastormgod - Initial commit                               │
            └─────────────────────────────────────────────────────────────────┘
                    │
2025-10-20          │  @2abet - Documentation fix (PR #1)
                    │
2025-11-06          │  @Thundastormgod - Ollama integration
                    │
2025-12-10          │  @mykael02 - Testing infrastructure
                    │
2025-12-30          │  Initial release v0.1.0
                    │
2026-01-02  ┌───────┴─────────────────────────────────────────────────────────┐
            │ Team expansion begins                                           │
            └─────────────────────────────────────────────────────────────────┘
                    │
2026-01-03          │  @ocheme1107 - SIEM detection rules
                    │
2026-01-04          │  @ocheme1107 + @jiboo2022 - SPL injection fix
                    │
2026-01-07          │  @laradipupo - Docker containerization
                    │
2026-01-13  ┌───────┴─────────────────────────────────────────────────────────┐
            │ @TemiAdebola - Event Sourcing + ContentFilter                   │
            └─────────────────────────────────────────────────────────────────┘
                    │
2026-01-14          │  @Shizoqua - Safety guardrails engine
                    │
2026-01-15          │  @bayulus - P0 security fixes, RateLimiter fixes
                    │
2026-01-16  ┌───────┴─────────────────────────────────────────────────────────┐
            │ @bayulus - Template Security Validator (74 tests)               │
            │ @jiboo2022 - Feedback API, CI fixes                             │
            └─────────────────────────────────────────────────────────────────┘
                    │
2026-01-17  ┌───────┴─────────────────────────────────────────────────────────┐
            │ @jiboo2022 - PR #92 merged (CI unblocked)                       │
            │ @jiboo2022 - PR #73 merged (Feedback API)                       │
            │ CI Pipeline: ✓ All workflows passing                            │
            └─────────────────────────────────────────────────────────────────┘
```

---

## Acknowledgments

### Superseded Contributions
- **@laradipupo** (PR #91) - CI pipeline fix attempt. Work was superseded by PR #92 but the effort is acknowledged.

### Code Reviews
- **@Thundastormgod** - Primary reviewer for most PRs
- **@laradipupo** - Approved PR #73 (Feedback API)

---

## Document Maintenance

This document should be updated when:
1. New PRs are merged
2. Significant commits are made directly to master
3. Collaborative work needs attribution
4. Squash merges hide individual contributions

**Maintained by:** ThreatSimGPT Core Team  
**Contact:** threatsimgpt@gmail.com
