# Type Registry Extension Request

**AIP Section:** 9.5  
**Target Registry:** <!-- e.g., allowed_counterparty_types, revocation_reason, denial_reason -->

---

## Proposed Addition

### New Value
```
registry_key: <!-- e.g., allowed_counterparty_types -->
value: <!-- e.g., enterprise_partner -->
description: <!-- What this value represents -->
```

### Rationale
<!-- Why is this value needed? What use case does it support? -->

### Backwards Compatibility
<!-- Does this change affect existing credentials? (Should be "No" for additions) -->

---

## Checklist

- [ ] I have read [AIP-TYPE-REGISTRY.md](../AIP-TYPE-REGISTRY.md)
- [ ] This value does not duplicate an existing type
- [ ] The naming follows existing conventions (lowercase_snake_case)
- [ ] I have provided clear description and use case
- [ ] I understand this requires OP maintainer review

---

## Technical Details

**Impact on existing delegations:** None / Requires migration  
**Validation rules:** <!-- Any special validation needed? -->  
**Related AIP sections:** <!-- e.g., 3.2 (Delegation), 4 (Revocation) -->

---

## Review Process

Per AIP Section 9.5:
1. PR submitted to observer-protocol/spec repo
2. OP maintainer review (minimum 1 approval)
3. Discussion period (minimum 48 hours for breaking changes)
4. Merge and version bump

**Reviewers:** @BTCBoyd @leo-bebchuk

---

*This template implements AIP v0.3.1 Section 9.5 Type Registry governance.*
