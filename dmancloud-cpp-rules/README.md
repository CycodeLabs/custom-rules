# dmancloud C++ rules (mirror)

Semgrep rules for C++ mirrored from [dmancloud/SemgrepRules](https://github.com/dmancloud/SemgrepRules)
so that Cycode custom SAST policies can be created from a source URL we control.

17 rules covering wire/frame parsing bounds checks (SBE, ring buffer, cursor/memcpy) and
TLS/SSL verification weaknesses. All are `languages: [cpp]`.

## Why this mirror exists

The Cycode custom-SAST API rejects a policy whose rule *content* is already registered in the
tenant ("Rule with the same content already exists in the system"), and a prior registration is
not always released when the policy is deleted. 14 of these 17 rules were wedged that way in the
EU tenant. Each rule here therefore carries a no-op marker in its metadata:

```yaml
metadata:
  cycode_rev: 1  # bumps the content hash so Cycode will import the rule
```

Semgrep ignores unknown metadata keys, so detection behavior is unchanged. Nothing else was
modified — rule ids, patterns, messages, severities, CWE/OWASP and the rest of the metadata are
byte-for-byte as upstream. Bump `cycode_rev` again if a re-import is ever needed.

## Loading these into Cycode

Severity comes from each rule's `severity:` field (the upstream tiers: `ERROR` = critical,
`WARNING` = high, `INFO` = medium), which is why the run maps them explicitly:

```bash
python3 cycode_policy_creator.py --dry-run \
  --cycode-api-url https://app.eu.cycode.com \
  --no-prefix --nice-names --strip-id-regex '^cycode-[0-9]+[a-z]?-' \
  --policy-suffix "(Gen2-c-cpp)" \
  --severity-map "ERROR=Critical,WARNING=High,INFO=Medium" \
  --rules-path dmancloud-cpp-rules \
  --github-base-url https://raw.githubusercontent.com/CycodeLabs/custom-rules/main/dmancloud-cpp-rules \
  generic
```

Use the **raw** base URL — some tenants fetch and parse the YAML at create time, and a
`/blob/` URL serves HTML, which fails validation. Drop `--dry-run` to create.

## Upstream

Upstream carries no license file; these are mirrored for internal Cycode policy provisioning.
Prefer upstream as the source of truth for rule logic and re-mirror if it changes.
