# Development and Testing

This guide covers the local checks that should be run before contributing to ANPU or preparing a release.

## Requirements

- Go 1.25 or newer.
- Git.
- Docker for container/integration validation.
- Nuclei is optional for built-in development; the test suite uses controlled fixtures and fake binaries where appropriate.

The module declares Go 1.25 in `go.mod`.

## Clone and build

```sh
git clone https://github.com/Marwanmorsy999/anpu
cd anpu
go build ./...
```

Build the CLI directly with:

```sh
go build -o anpu ./cmd/anpu
./anpu --help
```

## Formatting

CI rejects unformatted Go source. Check locally with:

```sh
gofmt -l $(find . -name '*.go')
```

An empty result means no Go files were reported as unformatted.

To format changed files:

```sh
gofmt -w path/to/file.go
```

## Static checks

Run:

```sh
go vet ./...
```

## Unit and integration tests

The normal test suite is:

```sh
go test ./...
```

The repository CI runs the stronger race-enabled form:

```sh
go test -v -race ./...
```

The suite covers command behavior, target validation, SSRF protections, analyzers, integrations, reporting, storage, scoring, and the scanner pipeline.

Some live-site coverage is intentionally opt-in. The live example test is skipped unless `ANPU_LIVE_TESTS=1` is explicitly provided.

## Security integration test

The repository also has a GitHub Actions security workflow that:

1. starts controlled Juice Shop containers;
2. builds ANPU;
3. runs an ANPU scan against the authorized test target;
4. validates the generated SARIF;
5. uploads reports; and
6. cleans up the containers.

This gives the project a real end-to-end path in addition to unit tests.

For local development, prefer controlled fixtures and local test servers instead of scanning third-party systems.

## Docker

The Docker build is part of CI. Validate it locally with:

```sh
docker build -t anpu .
```

The image can then be used for an authorized target with a mounted reports directory:

```sh
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  anpu scan https://staging.example.com \
  --profile standard \
  --sarif \
  --output /reports
```

## Full pre-release check

Run the same core checks used by CI:

```sh
gofmt -l $(find . -name '*.go')
go build ./...
go vet ./...
go test -v -race ./...
docker build -t anpu .
```

Then run the controlled end-to-end security workflow in GitHub Actions before publishing a release.

## Adding a scanner

A new scanner should implement the existing scanner/stage interfaces rather than coupling itself directly to the pipeline. The concrete wiring belongs in `cmd/anpu/scan.go`.

A typical workflow is:

1. create the analyzer under `internal/<name>/`;
2. implement the scanner interface;
3. add focused tests using local fixtures;
4. add the stage to the pipeline wiring;
5. document the engine in [`scanners.md`](scanners.md);
6. expose configuration/profile behavior where appropriate; and
7. run the full race-enabled suite.

Keep evidence grounded in actual observations. Do not fabricate versions, findings, or response details when the target could not be verified.

## Adding or changing a finding

Stable finding IDs are used by deduplication, scan comparison, and downstream reporting. When changing a finding, review its ID, title, severity, confidence, evidence, references, and score behavior together.

Update tests whenever detection conditions or severity logic change.

## External integrations

Nuclei is deliberately optional. Tests should cover both the available and unavailable paths without requiring a live Nuclei installation.

ZAP is currently a prepared interface rather than an implemented driver. Treat it as planned functionality until the integration has an actual driver and dedicated end-to-end coverage.

## Responsible development

ANPU is a security testing tool. Use only targets and environments for which you have explicit authorization. Local test fixtures, intentionally vulnerable applications, and isolated containers are the preferred development environments.
