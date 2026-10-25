# Validated Network Telemetry Collectors

This is a curated copy containing only the 33 tasks marked exactly `VALIDATED` in the project's real-world validation matrix. The other 7 tasks are omitted, including their entry points and shared-source schemas.

## Included task IDs

01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 15, 17, 18, 19, 20, 21, 24, 25, 27, 28, 29, 30, 31, 32, 33, 34, 36, 37, 39, 40

## Important scope

`VALIDATED` means a named source and scenario matched the evidence recorded in [`VALIDATION_STATUS.json`](VALIDATION_STATUS.json). It is not a claim of 100% correctness on every Linux distribution, kernel, service configuration, cloud, or production network. Snapshots are not lifecycle histories. Task 33 evidence validates NetworkPolicy object collection; dataplane enforcement was not separately tested.

Tasks excluded because they were single-trial, partial, or blocked: 14 (VALIDATED_SINGLE_TRIAL), 16 (PARTIAL), 22 (VALIDATED_SINGLE_TRIAL), 23 (VALIDATED_SINGLE_TRIAL), 26 (PARTIAL), 35 (BLOCKED), 38 (PARTIAL).

## Run independently

Each retained collector remains a separate Python command. No master workflow or scheduler is included. Run `python3 <collector>.py --help` for its options. Python standard library only; native source utilities and permissions vary by task.

Run the retained focused tests with `python3 -m unittest discover -v`. The historical raw evidence files remain in the original project’s `validation/` directory and are not copied into this curated repository. `VALIDATION_STATUS.json` preserves each retained task’s evidence reference and note; retain the original `validation/` tree alongside this release when publishing evidence. Review host-specific metadata before publishing it.
