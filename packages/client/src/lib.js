export * from './connection.js'

import {
  Delegation,
  Invocation,
  Receipt,
  invoke,
  Schema,
  DAG,
  ok,
  error,
} from '@le-space/ucanto-core'

export const delegate = Delegation.delegate
export { invoke, ok, error, Schema, DAG, Delegation, Invocation, Receipt }
