# @le-space/ucanto-client

`@le-space/ucanto-client` provides the tools necessary to create, sign, and send UCAN-based RPC invocations. It enables secure communication with UCAN-compliant services while ensuring proper authorization and delegation handling.

## What It Provides

- **UCAN Invocation Handling**: Creates and signs capability invocations.
- **Batch Invocation Support**: Enables multiple invocations in a single request.
- **Secure Communication**: Ensures interactions are cryptographically signed and verified.

## How It Fits with Other Modules

- [`@le-space/ucanto-core`](../core/README.md): Defines capability structures and execution logic.
- [`@le-space/ucanto-server`](../server/README.md): Processes invocations received from the client.
- [`@le-space/ucanto-interface`](../interface/README.md): Provides shared types for request and response handling.
- [`@le-space/ucanto-principal`](../principal/README.md): Manages cryptographic signing for invocations.
- [`@le-space/ucanto-transport`](../transport/README.md): Handles encoding and sending of requests.

For an overview and detailed usage information, refer to the [main `ucanto` README](../../Readme.md).

## Installation
```sh
npm install @le-space/ucanto-client
```

## Example Usage
```ts
import * as Client from '@le-space/ucanto-client';
import { ed25519 } from '@le-space/ucanto-principal';

const service = ed25519.parse(process.env.SERVICE_ID);
const issuer = ed25519.parse(process.env.CLIENT_KEYPAIR);

const invocation = await Client.invoke({
  issuer,
  audience: service,
  capability: {
    can: 'file/read',
    with: 'file://example.txt'
  }
});

const response = await client.execute(invocation);
if (response.error) {
  console.error('Invocation failed:', response.error);
} else {
  console.log('Invocation succeeded:', response.result);
}
```

For more details, see the [`ucanto` documentation](https://github.com/storacha/ucanto).