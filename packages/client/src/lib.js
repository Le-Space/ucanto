export * from './connection.js'

export * from '@le-space/ucanto-interface'
import { Delegation, invoke, Schema, DAG, ok, error } from '@le-space/ucanto-core'

export const delegate = Delegation.delegate
export { invoke, ok, error, Schema, DAG }
