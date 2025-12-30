"""
ThreatSimGPT Enterprise Test Suite
==================================

A comprehensive, production-grade testing framework featuring:
- Unit Tests (isolated component testing)
- Integration Tests (module interaction testing)
- End-to-End Tests (full workflow testing)
- Performance Tests (benchmarking and load testing)
- Security Tests (vulnerability scanning and fuzzing)
- Property-Based Tests (Hypothesis-driven testing)
- Mutation Tests (test quality validation)
- Contract Tests (API contract verification)

Test Pyramid:
                    ┌─────────┐
                    │  E2E    │  (Few, Slow, High Coverage)
                   ┌┴─────────┴┐
                   │Integration│
                  ┌┴───────────┴┐
                  │    Unit     │  (Many, Fast, Isolated)
                 └──────────────┘

Quality Gates:
- Unit Test Coverage: ≥80%
- Integration Test Coverage: ≥60%
- Mutation Score: ≥70%
- Performance Regression: <10%
"""

__version__ = "1.0.0"
__author__ = "ThreatSimGPT Team"
