# nix-p2p — project guide

## Design & architecture — read these first
- **PRD.md** — the durable design record: essence, key decisions, irreversibility
  map, risks, and the current Wave-2c authority. Read it before proposing or
  changing architecture. It is long-term and gives the overall architecture guide.
- **docs/** — design notes that expand the PRD at implementation altitude (e.g.
  `docs/peer-fabric-seam.md`, the pluggable P2P substrate seam). Read the note
  covering a subsystem before touching that subsystem. docs/ carry the
  churn-prone detail the PRD deliberately keeps out.
- **TESTING.md** — what "good" and "bad" observably mean; the oracles the gates enforce.
- **backlog/** — task state. Use the `backlog` CLI (with `--plain`); never edit
  backlog md files directly.

When PRD.md and a design note conflict, the PRD's Wave-2c reconciliation is
normative; when code and docs drift, fix the drift rather than trusting either blindly.
