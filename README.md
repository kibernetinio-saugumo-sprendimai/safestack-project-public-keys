# SafeStack project public keys

This repository contains only public project keys and the root-signed registry.
Private keys are stored offline and are never committed here.

Verify the registry with:

```bash
python3 key_registry.py verify --registry public-project-keys.json
```

The registry currently contains the public key for `safestack-audit_system` as `project-001`.
