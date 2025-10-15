# @le-space/ucanto-interface

`@le-space/ucanto-interface` provides shared type definitions and contracts used across the `ucanto` ecosystem. It ensures consistent and type-safe interactions between different modules, facilitating seamless integration.

## What It Provides
- **Shared Type Definitions**: Standardized types for capabilities, invocations, and responses.
- **Interface Contracts**: Defines clear API contracts for `ucanto` modules.
- **Type Safety**: Enhances reliability through TypeScript-based type checking.

## How It Fits with Other Modules
- [`@le-space/ucanto-core`](../core/README.md): Uses the interfaces to define and execute capabilities.
- [`@le-space/ucanto-server`](../server/README.md): Implements service logic based on interface definitions.
- [`@le-space/ucanto-transport`](../transport/README.md): Adopts standardized encoding and transport interfaces.
- [`@le-space/ucanto-principal`](../principal/README.md): Uses identity-related interfaces for cryptographic operations.
- [`@le-space/ucanto-client`](../client/README.md): Ensures consistent request and response structures.

For an overview and detailed usage information, refer to the [main `ucanto` README](../../Readme.md).

## Installation
```sh
npm install @le-space/ucanto-interface
```

## Example Usage
```ts
import { Capability, Invocation } from '@le-space/ucanto-interface';

const exampleCapability: Capability = {
  can: 'file/read',
  with: 'file://example.txt'
};

const exampleInvocation: Invocation = {
  capability: exampleCapability,
  issuer: 'did:key:xyz',
  audience: 'did:key:abc'
};
```

For more details, see the [`ucanto` documentation](https://github.com/storacha/ucanto).