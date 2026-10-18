# Installation

See [releases.md](releases.md) for verification details.

## One-liners

Linux/macOS:
```sh
curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
```

Windows:
```powershell
irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
```

Docker:
```sh
docker run --rm ghcr.io/marwanmorsy999/anpu scan https://example.com
```

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh -s -- --uninstall
ANPU_UNINSTALL=1 ANPU_PURGE=1 sh install.sh
```

```powershell
$env:ANPU_UNINSTALL = "1"; irm ... | iex
```

## Update

```sh
anpu update --check
anpu update
```