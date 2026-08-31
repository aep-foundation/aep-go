# Go examples

| Example                                                 | Demonstrates                                                                                  |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| [Agent and Service lifecycle](./agent-service/)         | Inspect, Claims, Enroll, API-key Grant, protected-resource authentication, and Revoke          |
| [Hosted identity Platform](./platform/)                 | Platform discovery, identity provisioning, delegated signing, and identity listing            |

Build every example with:

```sh
make examples
```

Each example is self-contained and uses ephemeral in-memory state. The role integration guides identify the interfaces that production applications must replace.
