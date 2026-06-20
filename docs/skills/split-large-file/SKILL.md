# Skill: Split Large File

**Trigger:** File exceeds 500 lines, or a change would push it over.

**Usage:** `python skills/split-large-file/run.py <file>`

## Steps
1. Map the public API surface — lists all exported symbols grouped by concern
2. Identify concern clusters — each cluster must be cohesive, fit under 500 lines
3. Create new files — name by concern, same package
4. Move implementations — keep interfaces with callers
5. Update exemption lists — remove old file from HARNESS.md exemptions
6. Verify — go build, go vet, make acceptance
