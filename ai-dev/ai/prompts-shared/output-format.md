# Review output format

Report only findings supported by current code, tests, contracts, or a named
standard. Distinguish observed fact from inference.

For each finding include:

| Field | Required content |
|---|---|
| Severity | Critical, High, Medium, Low, or Info |
| Title | Specific present-tense defect |
| Surface | SDK, stock binary, nested module, or external frontend |
| Location | Repository path and symbol/line |
| Evidence | Minimal reproducible code, test, configuration, or standard reference |
| Failure scenario | Concrete input, state, ordering, or outage |
| Impact and likelihood | Security, data, availability, compatibility, or maintainability consequence |
| Fix | Smallest actionable correction and required tests/docs |
| Risk/effort | Breaking-change risk and rough effort |

Sort by severity and avoid duplicate findings with the same root cause.

Conclude with:

- overall readiness;
- Critical/High counts;
- ship decision (`yes`, `no`, or a precise condition);
- must-fix items;
- explicitly deferred items; and
- validation that was run versus inferred.
