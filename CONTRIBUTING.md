# Contributing to FacetFS

FacetFS accepts focused issues and pull requests. Because network filesystem
bugs can cause data loss or security failures, behavior changes should include
tests and should clearly state the behavior they implement.

## Local checks

Run the full baseline before opening a pull request:

```sh
make check
make race
make build
```

New wire decoders must bound request-controlled allocations and include fuzz
coverage. Protocol behavior should be tested at the protocol level, with a real
client where practical.

Public API, locking, and protocol capability changes should explain the
tradeoffs in their issue or pull request description.

Do not describe experimental protocol support as compliant or conformant.
