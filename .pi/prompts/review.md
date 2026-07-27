<!-- Reviewer Agent: verify implementation -->
1. Read `AGENTS.md` and the applicable section of
   `docs/agent-os/EVALUATION.md`.
2. Run the relevant package/integration tests and the committed root gates.
3. Verify security behavior: no-store headers, Bearer challenge,
   anti-enumeration, and oracle-safe errors.
4. Verify architecture and quality: downward imports, real Memory
   implementations instead of mocks, budgets, and no emoji.
5. Confirm contract-coupled documentation changed in the same diff.
