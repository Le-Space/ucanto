# @le-space/ucanto-transport

`@le-space/ucanto-transport` provides encoding, decoding, and transport mechanisms for UCAN-based RPC. It ensures reliable communication between clients and servers using standardized serialization formats.

## What It Provides
- **Pluggable Transport Layer**: Supports multiple encoding formats like CAR and CBOR.
- **Standardized Encoding**: Ensures consistency in UCAN invocation serialization.
- **Extensible Communication**: Enables integration with various network protocols.

## How It Fits with Other Modules
- [`@le-space/ucanto-core`](../core/README.md): Uses transport mechanisms for executing capabilities.
- [`@le-space/ucanto-server`](../server/README.md): Relies on transport modules for request handling.
- [`@le-space/ucanto-interface`](../interface/README.md): Defines standard transport-related types.
- [`@le-space/ucanto-principal`](../principal/README.md): Facilitates secure communication using identity-based encryption.

For an overview and detailed usage information, refer to the [main `ucanto` README](../../Readme.md).

## Installation
```sh
npm install @le-space/ucanto-transport
```

## Example Usage
```ts
import * as CAR from '@le-space/ucanto-transport/car';
import * as CBOR from '@le-space/ucanto-transport/cbor';

const encoded = CAR.encode({ invocations: [] });
const decoded = CBOR.decode(encoded);
```

For more details, see the [`ucanto` documentation](https://github.com/storacha/ucanto).