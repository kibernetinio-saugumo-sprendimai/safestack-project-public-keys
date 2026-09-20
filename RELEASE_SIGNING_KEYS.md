# SafeStack release-signing keys

This file lists public SSH Ed25519 keys used to sign release hash manifests.
They are separate from the root-signed project identity registry in
`public-project-keys.json`.

## SafeStack Pi 5 release key — 2026

- **Fingerprint:** `SHA256:6bUvQeyGzXxDIUMnUyIoJPRbEeX3khAhRmYycwmgJq4`
- **Algorithm:** SSH Ed25519
- **Purpose:** `safestack-Pi-5-VPN/release/safestack-pi5.sha256`
- **Public key:** [`release-signing/safestack-pi5-2026.pub`](release-signing/safestack-pi5-2026.pub)

The matching private key is stored offline and is never committed here.
Verify a release with the public key and the repository's `VERIFY.md` procedure.
