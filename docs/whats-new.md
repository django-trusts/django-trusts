# What's new

Release announcements only; required actions live in [migrations](../migrates.md).

## 1.1.0

- User conditions and an optional override: [getting started](source/index.rst#user-conditions-and-overrides).
- Provisional bounded `along=` walks: [policy and renderer limits](../SECURITY_AUDIT.md#bounded-inherited-relationships).
- Intermediate-content filtering follows walks and delegation: [inquiry reference](dev/permission-inquiries.md#lower-level-and-intermediate-content-projections).
- SQL bind reuse and readable parameter tokens: [policy inspection](../SECURITY_AUDIT.md#authorization-policy-sql-and-lockfile).
- Delegated authority with live sponsor grants: [delegation contract](../SECURITY_AUDIT.md#delegated-authority).
- Lazy permitted-content querysets: [working example](source/index.rst#ask-permission-questions).
- Get users from content with either adapter: [inquiry reference](dev/permission-inquiries.md#users-from-content).
- Explicit Django group registrations and terminal permission collections: [relationship paths](../SECURITY_AUDIT.md#relationship-paths).
- Permission content-type isolation: [required upgrade action](../migrates.md#permission-content-type-must-match-the-object-267).
