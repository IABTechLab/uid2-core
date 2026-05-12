# UID2 Core

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review the governance rules [here](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md)

## Prerequisite

To setup dependencies before building, run the follow script

```bash
./setup_dependencies.sh
```

## Building

To run unit tests:

```
mvn clean test
```

To package application:

```
mvn package
```

To run application:

- for local debugging that loads salt and key stores from mock storage provider, use `config/local-config.json`:

```
mvn clean compile exec:java -Dvertex-configpath=conf/local-config.json
```

- for integration test, you need to prepare config and secrets in `conf/integ-config.json` to run core service that loads salt and key stores from aws s3:
  
```
mvn clean compile exec:java -Dvertx-config-path=conf/integ-config.json
```

## Verifying image provenance

Every non-snapshot image published by this repo's release workflow ships with a [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation, signed by GitHub's [Sigstore](https://www.sigstore.dev/) instance via the OIDC identity of the [shared publish workflow](https://github.com/IABTechLab/uid2-shared-actions). The attestation cryptographically binds the image digest to the source commit, the signing workflow, and the runner that built it.

To verify an image, install [`gh`](https://cli.github.com/) (≥ 2.49) and run:

```bash
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-core:<tag> \
  --owner IABTechLab \
  --signer-repo IABTechLab/uid2-shared-actions
```

A successful run prints `✓ Verification succeeded!` followed by the SLSA provenance fields — including `sourceRepositoryDigest` (the source commit), `workflow.path` (the signing workflow), and the runner identity.

Snapshot tags (`-SNAPSHOT` suffix) deliberately skip attestation. `gh attestation verify` returns `no attestations found` against a snapshot — that's expected.
