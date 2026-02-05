:robot: I have created a release *beep* *boop*
---


<details><summary>ucanto-principal: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-principal-v9.0.2...ucanto-principal-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* did prinicipal ([#149](https://github.com/Le-Space/ucanto/issues/149))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* Add WebAuthn Ed25519 varsig support to ucanto principal ([5b315c9](https://github.com/Le-Space/ucanto/commit/5b315c98704a8e8a40909ac804315897310e82ea))
* align implementation with receipt 0.2 spec ([#271](https://github.com/Le-Space/ucanto/issues/271)) ([aeea7e3](https://github.com/Le-Space/ucanto/commit/aeea7e3c7494143dce535792b0d53520e559c45a))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* did prinicipal ([#149](https://github.com/Le-Space/ucanto/issues/149)) ([4c11092](https://github.com/Le-Space/ucanto/commit/4c11092e420292af697bd5bec126112f9b961612))
* embedded key resolution ([#168](https://github.com/Le-Space/ucanto/issues/168)) ([5e650f3](https://github.com/Le-Space/ucanto/commit/5e650f376db79c690e4771695d1ff4e6deece40e))
* implement rsa signer / verifier ([#102](https://github.com/Le-Space/ucanto/issues/102)) ([8ed7777](https://github.com/Le-Space/ucanto/commit/8ed77770142259be03c3d6a8108365db1ab796b2))
* implement support for BLS keys ([#318](https://github.com/Le-Space/ucanto/issues/318)) ([0bee77e](https://github.com/Le-Space/ucanto/commit/0bee77e13174a1f964fe67fd25a3eaf6ee00f141))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108)) ([e2e03ff](https://github.com/Le-Space/ucanto/commit/e2e03ffeb35f00627335dbfd3e128e2cf9dcfdee))
* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310)) ([3d1adbf](https://github.com/Le-Space/ucanto/commit/3d1adbf0011db1a1d602040bbdc84b1e3721f62c))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update to latest dag-ucan ([#165](https://github.com/Le-Space/ucanto/issues/165)) ([20e50de](https://github.com/Le-Space/ucanto/commit/20e50de5e311781ee8dc10e32de4eb12e8df2080))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))


### Bug Fixes

* correct JSON syntax in principal package.json ([5e4d224](https://github.com/Le-Space/ucanto/commit/5e4d224ef2044c5353da99e606286ac77b717f8e))
* ed type export ([#154](https://github.com/Le-Space/ucanto/issues/154)) ([2f14271](https://github.com/Le-Space/ucanto/commit/2f142715ec7350f57b0a43374f699695292f6edd))
* expose multiformat ([#248](https://github.com/Le-Space/ucanto/issues/248)) ([9a74a0e](https://github.com/Le-Space/ucanto/commit/9a74a0e734809cfb38a7b4c976e0d7f2e4dcf4aa))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* parse should take strings ([#93](https://github.com/Le-Space/ucanto/issues/93)) ([db57d6b](https://github.com/Le-Space/ucanto/commit/db57d6bdf3ad989e4dc6e906d9b0bce4befbd735))
* **principal:** improve WebAuthn test exclusion pattern for TypeScript& ([a3a2200](https://github.com/Le-Space/ucanto/commit/a3a22005b3d91667eefe69f4e97238b79861aec6))
* **principal:** update webauthn/p256 verifiers ([8096adb](https://github.com/Le-Space/ucanto/commit/8096adb0cdda240b7d454f324291aa6ee6454683))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* toJSON behavior on the ucan.data ([#185](https://github.com/Le-Space/ucanto/issues/185)) ([d1ee6b6](https://github.com/Le-Space/ucanto/commit/d1ee6b6a0044d53359f0e20f631e3b86e4b94ab3))
* trigger interface upgrade for all packages ([#349](https://github.com/Le-Space/ucanto/issues/349)) ([255f0c1](https://github.com/Le-Space/ucanto/commit/255f0c1a7779ae9356e8f889e22b491a9789d334))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* type mapping regression ([#246](https://github.com/Le-Space/ucanto/issues/246)) ([e992549](https://github.com/Le-Space/ucanto/commit/e992549c3268e13512176ff45c9ee8f04b153556))
* upgrade dependencies ([#366](https://github.com/Le-Space/ucanto/issues/366)) ([bf6274c](https://github.com/Le-Space/ucanto/commit/bf6274ce637bab6a97f38065cf6c2b7eb10e3c24))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-client: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-client-v9.0.1...ucanto-client-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* Add WebAuthn Ed25519 varsig support to ucanto principal ([5b315c9](https://github.com/Le-Space/ucanto/commit/5b315c98704a8e8a40909ac804315897310e82ea))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* support execution of materialized invocations ([#199](https://github.com/Le-Space/ucanto/issues/199)) ([275bc24](https://github.com/Le-Space/ucanto/commit/275bc2439d81d0822c03ac62ba56f63d965d2622))
* **ucanto:** capability create / inovke methods ([#51](https://github.com/Le-Space/ucanto/issues/51)) ([ddf56b1](https://github.com/Le-Space/ucanto/commit/ddf56b1ec80ff6c0698255c531936d8eeab532fd))
* **ucanto:** upstream changes from w3 branch ([#54](https://github.com/Le-Space/ucanto/issues/54)) ([861e997](https://github.com/Le-Space/ucanto/commit/861e997e31c2a51195b8384eff5df656b6ec9efc))
* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310)) ([3d1adbf](https://github.com/Le-Space/ucanto/commit/3d1adbf0011db1a1d602040bbdc84b1e3721f62c))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274)) ([25abb67](https://github.com/Le-Space/ucanto/commit/25abb679a05b1f4010cdb949c71537ca2611d9c7))


### Bug Fixes

* add missing dependency on `@ucanto/principal` ([#317](https://github.com/Le-Space/ucanto/issues/317)) ([c62f9c2](https://github.com/Le-Space/ucanto/commit/c62f9c239de4b2a8931b26364d4c401533f2bd93))
* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* client imports ([#284](https://github.com/Le-Space/ucanto/issues/284)) ([9294392](https://github.com/Le-Space/ucanto/commit/92943927a401514be2c93bd02cc3592beedfea47))
* downgrade versions ([#158](https://github.com/Le-Space/ucanto/issues/158)) ([f814e75](https://github.com/Le-Space/ucanto/commit/f814e75a89d3ed7c3488a8cb7af8d94f0cfba440))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* **principal:** update webauthn/p256 verifiers ([8096adb](https://github.com/Le-Space/ucanto/commit/8096adb0cdda240b7d454f324291aa6ee6454683))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* remove invalid package exports ([d5a112b](https://github.com/Le-Space/ucanto/commit/d5a112ba7852c442a3af744f98c58ecbe23669ee))
* trigger interface upgrade for all packages ([#349](https://github.com/Le-Space/ucanto/issues/349)) ([255f0c1](https://github.com/Le-Space/ucanto/commit/255f0c1a7779ae9356e8f889e22b491a9789d334))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-core: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-core-v10.4.0...ucanto-core-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274))
* migrate schema to core ([#273](https://github.com/Le-Space/ucanto/issues/273))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* add principal schema ([#379](https://github.com/Le-Space/ucanto/issues/379)) ([4382120](https://github.com/Le-Space/ucanto/commit/43821209f1d63dba0dfa73d8e191a88b5a330a6e))
* add Schema.bytes ([#300](https://github.com/Le-Space/ucanto/issues/300)) ([2bbdd1c](https://github.com/Le-Space/ucanto/commit/2bbdd1c4725ec716bd06c512fec933d48e9820e0))
* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347)) ([58f7c13](https://github.com/Le-Space/ucanto/commit/58f7c13862b9c4581b06f190f25e9d6a0969239a))
* Add Uint64 support to schema ([#315](https://github.com/Le-Space/ucanto/issues/315)) ([2a74f92](https://github.com/Le-Space/ucanto/commit/2a74f92a7ea6da307e1dc4149f0d5a705842b659))
* Add WebAuthn Ed25519 varsig support to ucanto principal ([5b315c9](https://github.com/Le-Space/ucanto/commit/5b315c98704a8e8a40909ac804315897310e82ea))
* alight link API with multiformats ([#36](https://github.com/Le-Space/ucanto/issues/36)) ([0ec460e](https://github.com/Le-Space/ucanto/commit/0ec460e43ddda0bb3a3fea8a7881da1463154f36))
* align implementation with receipt 0.2 spec ([#271](https://github.com/Le-Space/ucanto/issues/271)) ([aeea7e3](https://github.com/Le-Space/ucanto/commit/aeea7e3c7494143dce535792b0d53520e559c45a))
* allow api inferring capabilities ([#259](https://github.com/Le-Space/ucanto/issues/259)) ([cd8cef8](https://github.com/Le-Space/ucanto/commit/cd8cef85dba4a612d9ff05abfa2b8dcfbc378499))
* archive/extract api for delegations ([#287](https://github.com/Le-Space/ucanto/issues/287)) ([75036c1](https://github.com/Le-Space/ucanto/commit/75036c1af6cb35ea564087aa1a3b0d76b0099476))
* capability provider API ([#34](https://github.com/Le-Space/ucanto/issues/34)) ([ea89f97](https://github.com/Le-Space/ucanto/commit/ea89f97125bb484a12ce3ca09a7884911a9fd4d6))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* **core:** add schema type for reading did bytes ([#360](https://github.com/Le-Space/ucanto/issues/360)) ([deb30a3](https://github.com/Le-Space/ucanto/commit/deb30a3de09fb0dc1d703635c21a254456431092))
* define `resolveDIDKey` server option ([#364](https://github.com/Le-Space/ucanto/issues/364)) ([15648a8](https://github.com/Le-Space/ucanto/commit/15648a8270a678ac5ed69fa42abd8e5808294ac5))
* delegation.toJSON ([#186](https://github.com/Le-Space/ucanto/issues/186)) ([f8ffa74](https://github.com/Le-Space/ucanto/commit/f8ffa74bcbb1376b54633003a7c2609f70135c70))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309)) ([2a59d8a](https://github.com/Le-Space/ucanto/commit/2a59d8a2fe97325afcdacd5b769c9e88f96488be))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement support for BLS keys ([#318](https://github.com/Le-Space/ucanto/issues/318)) ([0bee77e](https://github.com/Le-Space/ucanto/commit/0bee77e13174a1f964fe67fd25a3eaf6ee00f141))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* migrate schema to core ([#273](https://github.com/Le-Space/ucanto/issues/273)) ([ce95504](https://github.com/Le-Space/ucanto/commit/ce95504a0e7cf7caf49418016dbb924b4cbc2e82))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* support attach inline blocks in invocation and delegation ([#288](https://github.com/Le-Space/ucanto/issues/288)) ([c9d6f3e](https://github.com/Le-Space/ucanto/commit/c9d6f3eb0bddf84b64b9c40df75257e7a10c674c))
* support execution of materialized invocations ([#199](https://github.com/Le-Space/ucanto/issues/199)) ([275bc24](https://github.com/Le-Space/ucanto/commit/275bc2439d81d0822c03ac62ba56f63d965d2622))
* **ucanto:** capability create / inovke methods ([#51](https://github.com/Le-Space/ucanto/issues/51)) ([ddf56b1](https://github.com/Le-Space/ucanto/commit/ddf56b1ec80ff6c0698255c531936d8eeab532fd))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update to latest dag-ucan ([#165](https://github.com/Le-Space/ucanto/issues/165)) ([20e50de](https://github.com/Le-Space/ucanto/commit/20e50de5e311781ee8dc10e32de4eb12e8df2080))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* validate attestation from another service ([#369](https://github.com/Le-Space/ucanto/issues/369)) ([bac2cb0](https://github.com/Le-Space/ucanto/commit/bac2cb08bd67de97ef6a7360713e4fd1d0ae1d5c)), closes [#267](https://github.com/Le-Space/ucanto/issues/267)
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274)) ([25abb67](https://github.com/Le-Space/ucanto/commit/25abb679a05b1f4010cdb949c71537ca2611d9c7))


### Bug Fixes

* add link to receipt ([#351](https://github.com/Le-Space/ucanto/issues/351)) ([efa3506](https://github.com/Le-Space/ucanto/commit/efa3506efc333040e90daa8482c8eafb5dc81941))
* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* capture attachments links from capabilities and facts ([#298](https://github.com/Le-Space/ucanto/issues/298)) ([b2157fb](https://github.com/Le-Space/ucanto/commit/b2157fbf202654c4812387618bfcdb2442ecb027))
* cbor prepare encode wrongly identifying circular sturcture ([#327](https://github.com/Le-Space/ucanto/issues/327)) ([3c03c9d](https://github.com/Le-Space/ucanto/commit/3c03c9d3885578c139dd9d3619afed8728205148))
* **core:** force release ([9157252](https://github.com/Le-Space/ucanto/commit/9157252ea8a27a9431163cb1bd331f2be20fa867))
* **core:** force release ([16e7017](https://github.com/Le-Space/ucanto/commit/16e7017bb5a8d8d0edf98b08037e07e6877a0c85))
* **core:** force release ([d70b5a1](https://github.com/Le-Space/ucanto/commit/d70b5a19ea665a30506b3eb5b8ee510f4b4a55bd))
* **core:** force release ([49bdb68](https://github.com/Le-Space/ucanto/commit/49bdb6813c290978acd67777141cd2319639e911))
* correct JSON syntax errors and missing workspace dependencies ([18ef65d](https://github.com/Le-Space/ucanto/commit/18ef65ddf642cd1c4da3e3819f869e00b315b007))
* do not call exports import or export ([#217](https://github.com/Le-Space/ucanto/issues/217)) ([3c1ab06](https://github.com/Le-Space/ucanto/commit/3c1ab0601445398f8660de652a954e53d1c9f7aa))
* downgrade versions ([#158](https://github.com/Le-Space/ucanto/issues/158)) ([f814e75](https://github.com/Le-Space/ucanto/commit/f814e75a89d3ed7c3488a8cb7af8d94f0cfba440))
* exported anonymous class type may not be private or protected ([#373](https://github.com/Le-Space/ucanto/issues/373)) ([81d4d02](https://github.com/Le-Space/ucanto/commit/81d4d0262fc1a42920fb67899fa785003bfab2ca))
* message tag to 7.0.0 ([#282](https://github.com/Le-Space/ucanto/issues/282)) ([6ef3dcc](https://github.com/Le-Space/ucanto/commit/6ef3dcc1d45b65a7d932fd542c96721b0feea4c8))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* **principal:** update webauthn/p256 verifiers ([8096adb](https://github.com/Le-Space/ucanto/commit/8096adb0cdda240b7d454f324291aa6ee6454683))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* toJSON behavior on the ucan.data ([#185](https://github.com/Le-Space/ucanto/issues/185)) ([d1ee6b6](https://github.com/Le-Space/ucanto/commit/d1ee6b6a0044d53359f0e20f631e3b86e4b94ab3))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* typo ([#145](https://github.com/Le-Space/ucanto/issues/145)) ([18b3fd1](https://github.com/Le-Space/ucanto/commit/18b3fd17e8d7671dc76a238723cb8d524b29cba3))
* update @ipld/car and @ipld/dag-cbor deps ([#120](https://github.com/Le-Space/ucanto/issues/120)) ([5dcd7a5](https://github.com/Le-Space/ucanto/commit/5dcd7a5788dfd126f332b126f7ad1215972f29c4))
* upgrade dependencies ([#366](https://github.com/Le-Space/ucanto/issues/366)) ([bf6274c](https://github.com/Le-Space/ucanto/commit/bf6274ce637bab6a97f38065cf6c2b7eb10e3c24))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-interface: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-interface-v11.0.0...ucanto-interface-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381))
* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220))
* did prinicipal ([#149](https://github.com/Le-Space/ucanto/issues/149))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* add principal schema ([#379](https://github.com/Le-Space/ucanto/issues/379)) ([4382120](https://github.com/Le-Space/ucanto/commit/43821209f1d63dba0dfa73d8e191a88b5a330a6e))
* add revocation checker hook ([#320](https://github.com/Le-Space/ucanto/issues/320)) ([0c2dbc6](https://github.com/Le-Space/ucanto/commit/0c2dbc6cdda6bdfad0b1c2ee33eaf37bfd470540))
* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347)) ([58f7c13](https://github.com/Le-Space/ucanto/commit/58f7c13862b9c4581b06f190f25e9d6a0969239a))
* Add WebAuthn Ed25519 varsig support to ucanto principal ([5b315c9](https://github.com/Le-Space/ucanto/commit/5b315c98704a8e8a40909ac804315897310e82ea))
* alight link API with multiformats ([#36](https://github.com/Le-Space/ucanto/issues/36)) ([0ec460e](https://github.com/Le-Space/ucanto/commit/0ec460e43ddda0bb3a3fea8a7881da1463154f36))
* align implementation with receipt 0.2 spec ([#271](https://github.com/Le-Space/ucanto/issues/271)) ([aeea7e3](https://github.com/Le-Space/ucanto/commit/aeea7e3c7494143dce535792b0d53520e559c45a))
* allow alternative audience for server ([#371](https://github.com/Le-Space/ucanto/issues/371)) ([d793091](https://github.com/Le-Space/ucanto/commit/d793091d7a6fac702231b92e1181d4216ebce93a))
* allow api inferring capabilities ([#259](https://github.com/Le-Space/ucanto/issues/259)) ([cd8cef8](https://github.com/Le-Space/ucanto/commit/cd8cef85dba4a612d9ff05abfa2b8dcfbc378499))
* archive/extract api for delegations ([#287](https://github.com/Le-Space/ucanto/issues/287)) ([75036c1](https://github.com/Le-Space/ucanto/commit/75036c1af6cb35ea564087aa1a3b0d76b0099476))
* capability provider API ([#34](https://github.com/Le-Space/ucanto/issues/34)) ([ea89f97](https://github.com/Le-Space/ucanto/commit/ea89f97125bb484a12ce3ca09a7884911a9fd4d6))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* configurable audience handlers ([#257](https://github.com/Le-Space/ucanto/issues/257)) ([f8d001c](https://github.com/Le-Space/ucanto/commit/f8d001cf721b0e96757fa372993f2fe6b6e8d520))
* define `resolveDIDKey` server option ([#364](https://github.com/Le-Space/ucanto/issues/364)) ([15648a8](https://github.com/Le-Space/ucanto/commit/15648a8270a678ac5ed69fa42abd8e5808294ac5))
* delegation.toJSON ([#186](https://github.com/Le-Space/ucanto/issues/186)) ([f8ffa74](https://github.com/Le-Space/ucanto/commit/f8ffa74bcbb1376b54633003a7c2609f70135c70))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* did prinicipal ([#149](https://github.com/Le-Space/ucanto/issues/149)) ([4c11092](https://github.com/Le-Space/ucanto/commit/4c11092e420292af697bd5bec126112f9b961612))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309)) ([2a59d8a](https://github.com/Le-Space/ucanto/commit/2a59d8a2fe97325afcdacd5b769c9e88f96488be))
* embedded key resolution ([#168](https://github.com/Le-Space/ucanto/issues/168)) ([5e650f3](https://github.com/Le-Space/ucanto/commit/5e650f376db79c690e4771695d1ff4e6deece40e))
* Impelment InferInvokedCapability per [#99](https://github.com/Le-Space/ucanto/issues/99) ([#100](https://github.com/Le-Space/ucanto/issues/100)) ([fc5a2ac](https://github.com/Le-Space/ucanto/commit/fc5a2ace33f2a3599a654d8edd1641d111032074))
* implement .delegate on capabilities ([#110](https://github.com/Le-Space/ucanto/issues/110)) ([fd0bb9d](https://github.com/Le-Space/ucanto/commit/fd0bb9da58836c05d6ee9f60cd6b1cb6b747e3b1))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement rsa signer / verifier ([#102](https://github.com/Le-Space/ucanto/issues/102)) ([8ed7777](https://github.com/Le-Space/ucanto/commit/8ed77770142259be03c3d6a8108365db1ab796b2))
* implement support for BLS keys ([#318](https://github.com/Le-Space/ucanto/issues/318)) ([0bee77e](https://github.com/Le-Space/ucanto/commit/0bee77e13174a1f964fe67fd25a3eaf6ee00f141))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251)) ([6e48019](https://github.com/Le-Space/ucanto/commit/6e48019b905787b64b194bc0de0b1cd2c2cc3edc))
* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381)) ([6254993](https://github.com/Le-Space/ucanto/commit/6254993eb7368040a6232d50a1d68a123d2ed799))
* rip out special handling of my: and as: capabilities ([#109](https://github.com/Le-Space/ucanto/issues/109)) ([3ec8e64](https://github.com/Le-Space/ucanto/commit/3ec8e6434a096221bf72193e074810cc18dd5cd8))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* support attach inline blocks in invocation and delegation ([#288](https://github.com/Le-Space/ucanto/issues/288)) ([c9d6f3e](https://github.com/Le-Space/ucanto/commit/c9d6f3eb0bddf84b64b9c40df75257e7a10c674c))
* support execution of materialized invocations ([#199](https://github.com/Le-Space/ucanto/issues/199)) ([275bc24](https://github.com/Le-Space/ucanto/commit/275bc2439d81d0822c03ac62ba56f63d965d2622))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108)) ([e2e03ff](https://github.com/Le-Space/ucanto/commit/e2e03ffeb35f00627335dbfd3e128e2cf9dcfdee))
* **ucanto:** capability create / inovke methods ([#51](https://github.com/Le-Space/ucanto/issues/51)) ([ddf56b1](https://github.com/Le-Space/ucanto/commit/ddf56b1ec80ff6c0698255c531936d8eeab532fd))
* **ucanto:** upstream changes from w3 branch ([#54](https://github.com/Le-Space/ucanto/issues/54)) ([861e997](https://github.com/Le-Space/ucanto/commit/861e997e31c2a51195b8384eff5df656b6ec9efc))
* **ucanto:** URI protocol type retention & capability constructors ([e291544](https://github.com/Le-Space/ucanto/commit/e2915447254990d6e2384ff79a1da38120426ed5))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update to latest dag-ucan ([#165](https://github.com/Le-Space/ucanto/issues/165)) ([20e50de](https://github.com/Le-Space/ucanto/commit/20e50de5e311781ee8dc10e32de4eb12e8df2080))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220)) ([8a578ae](https://github.com/Le-Space/ucanto/commit/8a578ae403f7270fc741f8aef07f1d3621fb29f9))
* validate attestation from another service ([#369](https://github.com/Le-Space/ucanto/issues/369)) ([bac2cb0](https://github.com/Le-Space/ucanto/commit/bac2cb08bd67de97ef6a7360713e4fd1d0ae1d5c)), closes [#267](https://github.com/Le-Space/ucanto/issues/267)
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274)) ([25abb67](https://github.com/Le-Space/ucanto/commit/25abb679a05b1f4010cdb949c71537ca2611d9c7))


### Bug Fixes

* .provide inference regression ([#242](https://github.com/Le-Space/ucanto/issues/242)) ([ab155b7](https://github.com/Le-Space/ucanto/commit/ab155b71024878b7f31cddd6031c45a0e8a2fff1))
* add link to receipt ([#351](https://github.com/Le-Space/ucanto/issues/351)) ([efa3506](https://github.com/Le-Space/ucanto/commit/efa3506efc333040e90daa8482c8eafb5dc81941))
* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* message tag to 7.0.0 ([#282](https://github.com/Le-Space/ucanto/issues/282)) ([6ef3dcc](https://github.com/Le-Space/ucanto/commit/6ef3dcc1d45b65a7d932fd542c96721b0feea4c8))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* **principal:** update webauthn/p256 verifiers ([8096adb](https://github.com/Le-Space/ucanto/commit/8096adb0cdda240b7d454f324291aa6ee6454683))
* remove non-existing exports from map ([8f1a75c](https://github.com/Le-Space/ucanto/commit/8f1a75cea5a7d63435ec265dbd4bb7ed26c8bb4c))
* **server:** loosen requirements on statics ([#353](https://github.com/Le-Space/ucanto/issues/353)) ([6de27c0](https://github.com/Le-Space/ucanto/commit/6de27c0f19790d9def1df2f2e299fa4f0996ded9))
* toJSON behavior on the ucan.data ([#185](https://github.com/Le-Space/ucanto/issues/185)) ([d1ee6b6](https://github.com/Le-Space/ucanto/commit/d1ee6b6a0044d53359f0e20f631e3b86e4b94ab3))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* upgrade dependencies ([#366](https://github.com/Le-Space/ucanto/issues/366)) ([bf6274c](https://github.com/Le-Space/ucanto/commit/bf6274ce637bab6a97f38065cf6c2b7eb10e3c24))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-server: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-server-v11.0.0...ucanto-server-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381))
* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* add revocation checker hook ([#320](https://github.com/Le-Space/ucanto/issues/320)) ([0c2dbc6](https://github.com/Le-Space/ucanto/commit/0c2dbc6cdda6bdfad0b1c2ee33eaf37bfd470540))
* add support for embedded effects ([#347](https://github.com/Le-Space/ucanto/issues/347)) ([58f7c13](https://github.com/Le-Space/ucanto/commit/58f7c13862b9c4581b06f190f25e9d6a0969239a))
* alight link API with multiformats ([#36](https://github.com/Le-Space/ucanto/issues/36)) ([0ec460e](https://github.com/Le-Space/ucanto/commit/0ec460e43ddda0bb3a3fea8a7881da1463154f36))
* allow alternative audience for server ([#371](https://github.com/Le-Space/ucanto/issues/371)) ([d793091](https://github.com/Le-Space/ucanto/commit/d793091d7a6fac702231b92e1181d4216ebce93a))
* capability provider API ([#34](https://github.com/Le-Space/ucanto/issues/34)) ([ea89f97](https://github.com/Le-Space/ucanto/commit/ea89f97125bb484a12ce3ca09a7884911a9fd4d6))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* configurable audience handlers ([#257](https://github.com/Le-Space/ucanto/issues/257)) ([f8d001c](https://github.com/Le-Space/ucanto/commit/f8d001cf721b0e96757fa372993f2fe6b6e8d520))
* define `resolveDIDKey` server option ([#364](https://github.com/Le-Space/ucanto/issues/364)) ([15648a8](https://github.com/Le-Space/ucanto/commit/15648a8270a678ac5ed69fa42abd8e5808294ac5))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* effects support ([#309](https://github.com/Le-Space/ucanto/issues/309)) ([2a59d8a](https://github.com/Le-Space/ucanto/commit/2a59d8a2fe97325afcdacd5b769c9e88f96488be))
* embedded key resolution ([#168](https://github.com/Le-Space/ucanto/issues/168)) ([5e650f3](https://github.com/Le-Space/ucanto/commit/5e650f376db79c690e4771695d1ff4e6deece40e))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251)) ([6e48019](https://github.com/Le-Space/ucanto/commit/6e48019b905787b64b194bc0de0b1cd2c2cc3edc))
* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381)) ([6254993](https://github.com/Le-Space/ucanto/commit/6254993eb7368040a6232d50a1d68a123d2ed799))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108)) ([e2e03ff](https://github.com/Le-Space/ucanto/commit/e2e03ffeb35f00627335dbfd3e128e2cf9dcfdee))
* **ucanto:** capability create / inovke methods ([#51](https://github.com/Le-Space/ucanto/issues/51)) ([ddf56b1](https://github.com/Le-Space/ucanto/commit/ddf56b1ec80ff6c0698255c531936d8eeab532fd))
* **ucanto:** upstream changes from w3 branch ([#54](https://github.com/Le-Space/ucanto/issues/54)) ([861e997](https://github.com/Le-Space/ucanto/commit/861e997e31c2a51195b8384eff5df656b6ec9efc))
* **ucanto:** URI protocol type retention & capability constructors ([e291544](https://github.com/Le-Space/ucanto/commit/e2915447254990d6e2384ff79a1da38120426ed5))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220)) ([8a578ae](https://github.com/Le-Space/ucanto/commit/8a578ae403f7270fc741f8aef07f1d3621fb29f9))
* validate attestation from another service ([#369](https://github.com/Le-Space/ucanto/issues/369)) ([bac2cb0](https://github.com/Le-Space/ucanto/commit/bac2cb08bd67de97ef6a7360713e4fd1d0ae1d5c)), closes [#267](https://github.com/Le-Space/ucanto/issues/267)
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274)) ([25abb67](https://github.com/Le-Space/ucanto/commit/25abb679a05b1f4010cdb949c71537ca2611d9c7))


### Bug Fixes

* .provide inference regression ([#242](https://github.com/Le-Space/ucanto/issues/242)) ([ab155b7](https://github.com/Le-Space/ucanto/commit/ab155b71024878b7f31cddd6031c45a0e8a2fff1))
* add missing dependency on `@ucanto/principal` ([#317](https://github.com/Le-Space/ucanto/issues/317)) ([c62f9c2](https://github.com/Le-Space/ucanto/commit/c62f9c239de4b2a8931b26364d4c401533f2bd93))
* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* dependency versions ([#322](https://github.com/Le-Space/ucanto/issues/322)) ([5fdfc4b](https://github.com/Le-Space/ucanto/commit/5fdfc4b1cd61e8f796d704bc1cf82984f25a2e96))
* downgrade versions ([#158](https://github.com/Le-Space/ucanto/issues/158)) ([f814e75](https://github.com/Le-Space/ucanto/commit/f814e75a89d3ed7c3488a8cb7af8d94f0cfba440))
* ensure `@ucanto/server` depends on v8 deps ([#313](https://github.com/Le-Space/ucanto/issues/313)) ([54268cd](https://github.com/Le-Space/ucanto/commit/54268cd47806d789fba7daffd1cdc50ca944833a))
* error inference of provide ([#291](https://github.com/Le-Space/ucanto/issues/291)) ([5ed3651](https://github.com/Le-Space/ucanto/commit/5ed3651212aa03ecde18154f7bb4c31e52bc60d3))
* inference of provide function ([#289](https://github.com/Le-Space/ucanto/issues/289)) ([e72af9d](https://github.com/Le-Space/ucanto/commit/e72af9df01e670850115223d7a6bede9d46be9f2))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* return 400 Bad Request for malformed payloads ([#375](https://github.com/Le-Space/ucanto/issues/375)) ([3eb6a63](https://github.com/Le-Space/ucanto/commit/3eb6a632b284a2762ce9c7bced27c49023744558))
* server verifier to support RSA and ed ([#142](https://github.com/Le-Space/ucanto/issues/142)) ([7317e71](https://github.com/Le-Space/ucanto/commit/7317e7122e105271f50d20d88c8bf2bb3a3d2575))
* **server:** exclude test files from TypeScript compilation& ([cc4924a](https://github.com/Le-Space/ucanto/commit/cc4924afff88d869746469eb3f65ad09e61e5671))
* **server:** force release ([473e5a6](https://github.com/Le-Space/ucanto/commit/473e5a6fbe5dcc18861da4f68d4990532461d730))
* **server:** force release ([614eba4](https://github.com/Le-Space/ucanto/commit/614eba4bca9175307028e2dd2bdd77c4841e11ae))
* **server:** generarting invaild typedefs ([#91](https://github.com/Le-Space/ucanto/issues/91)) ([f528031](https://github.com/Le-Space/ucanto/commit/f528031121e9cd7f17f106c737fafae15f928776))
* **server:** loosen requirements on statics ([#353](https://github.com/Le-Space/ucanto/issues/353)) ([6de27c0](https://github.com/Le-Space/ucanto/commit/6de27c0f19790d9def1df2f2e299fa4f0996ded9))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* **ucanto:** capability provider inference ([#52](https://github.com/Le-Space/ucanto/issues/52)) ([4fa6876](https://github.com/Le-Space/ucanto/commit/4fa68762ca69f304515d56f9b658ddba30fb51a7))
* versions ([#131](https://github.com/Le-Space/ucanto/issues/131)) ([88b87a7](https://github.com/Le-Space/ucanto/commit/88b87a7f3a32c02a22ddffcb8f38199445097133))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-transport: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-transport-v9.2.0...ucanto-transport-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* alight link API with multiformats ([#36](https://github.com/Le-Space/ucanto/issues/36)) ([0ec460e](https://github.com/Le-Space/ucanto/commit/0ec460e43ddda0bb3a3fea8a7881da1463154f36))
* align implementation with receipt 0.2 spec ([#271](https://github.com/Le-Space/ucanto/issues/271)) ([aeea7e3](https://github.com/Le-Space/ucanto/commit/aeea7e3c7494143dce535792b0d53520e559c45a))
* capability provider API ([#34](https://github.com/Le-Space/ucanto/issues/34)) ([ea89f97](https://github.com/Le-Space/ucanto/commit/ea89f97125bb484a12ce3ca09a7884911a9fd4d6))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* http transport includes more information in error message when encountering non-ok http response ([d5f6916](https://github.com/Le-Space/ucanto/commit/d5f6916a41447bcc32bfbd9378da2b4779ca2136))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* support execution of materialized invocations ([#199](https://github.com/Le-Space/ucanto/issues/199)) ([275bc24](https://github.com/Le-Space/ucanto/commit/275bc2439d81d0822c03ac62ba56f63d965d2622))
* **transport:** support custom headers in HTTP transport ([#376](https://github.com/Le-Space/ucanto/issues/376)) ([a673222](https://github.com/Le-Space/ucanto/commit/a67322283f8a4f3f40f5bc3ea0d5f4e132d0a6a1))
* **ucanto:** upstream changes from w3 branch ([#54](https://github.com/Le-Space/ucanto/issues/54)) ([861e997](https://github.com/Le-Space/ucanto/commit/861e997e31c2a51195b8384eff5df656b6ec9efc))
* **ucanto:** URI protocol type retention & capability constructors ([e291544](https://github.com/Le-Space/ucanto/commit/e2915447254990d6e2384ff79a1da38120426ed5))
* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310)) ([3d1adbf](https://github.com/Le-Space/ucanto/commit/3d1adbf0011db1a1d602040bbdc84b1e3721f62c))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* versioned wire transport ([#274](https://github.com/Le-Space/ucanto/issues/274)) ([25abb67](https://github.com/Le-Space/ucanto/commit/25abb679a05b1f4010cdb949c71537ca2611d9c7))


### Bug Fixes

* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* car imports ([#262](https://github.com/Le-Space/ucanto/issues/262)) ([d3a7f91](https://github.com/Le-Space/ucanto/commit/d3a7f91e80c5885451014b6a85594d180f17125c))
* default fetch implementation called on non Window object ([#88](https://github.com/Le-Space/ucanto/issues/88)) ([66a22ee](https://github.com/Le-Space/ucanto/commit/66a22eeb749e4f8091e5bfe832af36deb4dfff2e))
* do not use frozen object for headers ([#334](https://github.com/Le-Space/ucanto/issues/334)) ([1abd266](https://github.com/Le-Space/ucanto/commit/1abd26646508c5e21f886dcb96bc0d36b4c0e458))
* do not use frozen request headers ([#336](https://github.com/Le-Space/ucanto/issues/336)) ([fcdac7b](https://github.com/Le-Space/ucanto/commit/fcdac7b212c56b27080a7ecea09185eeac03655f))
* downgrade versions ([#158](https://github.com/Le-Space/ucanto/issues/158)) ([f814e75](https://github.com/Le-Space/ucanto/commit/f814e75a89d3ed7c3488a8cb7af8d94f0cfba440))
* export legacy request/response ([#294](https://github.com/Le-Space/ucanto/issues/294)) ([429c15b](https://github.com/Le-Space/ucanto/commit/429c15b6e5dd5fda6c15a94514d6690bc9ac058b))
* FetchResponse type ([#113](https://github.com/Le-Space/ucanto/issues/113)) ([9397eb6](https://github.com/Le-Space/ucanto/commit/9397eb6449d0e2ba30c0da7402f3beda4980ed73))
* message tag to 7.0.0 ([#282](https://github.com/Le-Space/ucanto/issues/282)) ([6ef3dcc](https://github.com/Le-Space/ucanto/commit/6ef3dcc1d45b65a7d932fd542c96721b0feea4c8))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* trigger interface upgrade for all packages ([#349](https://github.com/Le-Space/ucanto/issues/349)) ([255f0c1](https://github.com/Le-Space/ucanto/commit/255f0c1a7779ae9356e8f889e22b491a9789d334))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* type exports ([#280](https://github.com/Le-Space/ucanto/issues/280)) ([38c1745](https://github.com/Le-Space/ucanto/commit/38c1745ed7b8da9d0106ec0fea00b9b8e8225bc7))
* update @ipld/car and @ipld/dag-cbor deps ([#120](https://github.com/Le-Space/ucanto/issues/120)) ([5dcd7a5](https://github.com/Le-Space/ucanto/commit/5dcd7a5788dfd126f332b126f7ad1215972f29c4))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

<details><summary>ucanto-validator: 9.0.0</summary>

## [9.0.0](https://github.com/Le-Space/ucanto/compare/ucanto-validator-v10.0.0...ucanto-validator-v9.0.0) (2026-02-05)


###   BREAKING CHANGES

* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381))
* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310))
* migrate schema to core ([#273](https://github.com/Le-Space/ucanto/issues/273))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220))
* wildcard support in capabilies ([#218](https://github.com/Le-Space/ucanto/issues/218))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90))

### Features

* add revocation checker hook ([#320](https://github.com/Le-Space/ucanto/issues/320)) ([0c2dbc6](https://github.com/Le-Space/ucanto/commit/0c2dbc6cdda6bdfad0b1c2ee33eaf37bfd470540))
* alight link API with multiformats ([#36](https://github.com/Le-Space/ucanto/issues/36)) ([0ec460e](https://github.com/Le-Space/ucanto/commit/0ec460e43ddda0bb3a3fea8a7881da1463154f36))
* capability provider API ([#34](https://github.com/Le-Space/ucanto/issues/34)) ([ea89f97](https://github.com/Le-Space/ucanto/commit/ea89f97125bb484a12ce3ca09a7884911a9fd4d6))
* cause release ([#235](https://github.com/Le-Space/ucanto/issues/235)) ([168ac01](https://github.com/Le-Space/ucanto/commit/168ac018b51e93998190d3196aec93fe44f082e5))
* cherry pick changes from uploads-v2 demo ([#43](https://github.com/Le-Space/ucanto/issues/43)) ([4308fd2](https://github.com/Le-Space/ucanto/commit/4308fd2f392b9fcccc52af64432dcb04c8257e0b))
* configurable audience handlers ([#257](https://github.com/Le-Space/ucanto/issues/257)) ([f8d001c](https://github.com/Le-Space/ucanto/commit/f8d001cf721b0e96757fa372993f2fe6b6e8d520))
* delgation iterate, more errors and types  ([0606168](https://github.com/Le-Space/ucanto/commit/0606168313d17d66bcc1ad6091440765e1700a4f))
* embedded key resolution ([#168](https://github.com/Le-Space/ucanto/issues/168)) ([5e650f3](https://github.com/Le-Space/ucanto/commit/5e650f376db79c690e4771695d1ff4e6deece40e))
* Impelment InferInvokedCapability per [#99](https://github.com/Le-Space/ucanto/issues/99) ([#100](https://github.com/Le-Space/ucanto/issues/100)) ([fc5a2ac](https://github.com/Le-Space/ucanto/commit/fc5a2ace33f2a3599a654d8edd1641d111032074))
* implement .delegate on capabilities ([#110](https://github.com/Le-Space/ucanto/issues/110)) ([fd0bb9d](https://github.com/Le-Space/ucanto/commit/fd0bb9da58836c05d6ee9f60cd6b1cb6b747e3b1))
* implement dictionary schema ([#192](https://github.com/Le-Space/ucanto/issues/192)) ([a872395](https://github.com/Le-Space/ucanto/commit/a8723950a42636b5da658c4e8272a46a7a899e6d))
* implement invocation receipts ([#266](https://github.com/Le-Space/ucanto/issues/266)) ([5341416](https://github.com/Le-Space/ucanto/commit/5341416a5f1ba5048c41476bb6c6059556e8e27b))
* implement sync car decode ([#253](https://github.com/Le-Space/ucanto/issues/253)) ([40acaac](https://github.com/Le-Space/ucanto/commit/40acaac52870a68a358370bb1b3a5f4f081943d7))
* migrate from [@ucanto](https://github.com/ucanto) to @le-space/ucanto namespace& ([26dc44c](https://github.com/Le-Space/ucanto/commit/26dc44c27c5c68b6256c453036d224d5f251bafb))
* migrate schema to core ([#273](https://github.com/Le-Space/ucanto/issues/273)) ([ce95504](https://github.com/Le-Space/ucanto/commit/ce95504a0e7cf7caf49418016dbb924b4cbc2e82))
* refactor into monorepo ([#13](https://github.com/Le-Space/ucanto/issues/13)) ([1f99506](https://github.com/Le-Space/ucanto/commit/1f995064ec6e5953118c2dd1065ee6be959f25b9))
* remove canIssue hook default from the server ([#251](https://github.com/Le-Space/ucanto/issues/251)) ([6e48019](https://github.com/Le-Space/ucanto/commit/6e48019b905787b64b194bc0de0b1cd2c2cc3edc))
* resolve multiple verifiers ([#381](https://github.com/Le-Space/ucanto/issues/381)) ([6254993](https://github.com/Le-Space/ucanto/commit/6254993eb7368040a6232d50a1d68a123d2ed799))
* rip out special handling of my: and as: capabilities ([#109](https://github.com/Le-Space/ucanto/issues/109)) ([3ec8e64](https://github.com/Le-Space/ucanto/commit/3ec8e6434a096221bf72193e074810cc18dd5cd8))
* setup pnpm & release-please ([84ac7f1](https://github.com/Le-Space/ucanto/commit/84ac7f12e5a66ee4919fa7527858dc916850e3e0))
* switch decoder API to zod like schema API ([#108](https://github.com/Le-Space/ucanto/issues/108)) ([e2e03ff](https://github.com/Le-Space/ucanto/commit/e2e03ffeb35f00627335dbfd3e128e2cf9dcfdee))
* **ucanto:** capability create / inovke methods ([#51](https://github.com/Le-Space/ucanto/issues/51)) ([ddf56b1](https://github.com/Le-Space/ucanto/commit/ddf56b1ec80ff6c0698255c531936d8eeab532fd))
* **ucanto:** URI protocol type retention & capability constructors ([e291544](https://github.com/Le-Space/ucanto/commit/e2915447254990d6e2384ff79a1da38120426ed5))
* update `@ucanto/interface` dependencies ([#310](https://github.com/Le-Space/ucanto/issues/310)) ([3d1adbf](https://github.com/Le-Space/ucanto/commit/3d1adbf0011db1a1d602040bbdc84b1e3721f62c))
* update dag-ucan, types and names ([#90](https://github.com/Le-Space/ucanto/issues/90)) ([cd792c9](https://github.com/Le-Space/ucanto/commit/cd792c934fbd358d6ccfa5d02f205b14b5f2e14e))
* update multiformats ([#197](https://github.com/Le-Space/ucanto/issues/197)) ([b92a6c6](https://github.com/Le-Space/ucanto/commit/b92a6c6f5c066890a25e62205ff9848b1fb8dde1))
* update session API ([#227](https://github.com/Le-Space/ucanto/issues/227)) ([9bbb2f7](https://github.com/Le-Space/ucanto/commit/9bbb2f796fd57ebe1ecd2112de1927b23a1577bd))
* update ucanto to invocation spec compatible result type ([#272](https://github.com/Le-Space/ucanto/issues/272)) ([b124ed8](https://github.com/Le-Space/ucanto/commit/b124ed8299a94e5a6b5abcb7cd075dd46ac4139d))
* upgrade to ucan 0.9 ([#95](https://github.com/Le-Space/ucanto/issues/95)) ([b752b39](https://github.com/Le-Space/ucanto/commit/b752b398950120d6121badcdbb639f4dc9ce8794))
* upgrades to multiformats@10 ([#117](https://github.com/Le-Space/ucanto/issues/117)) ([61dc4ca](https://github.com/Le-Space/ucanto/commit/61dc4cafece3365bbf60f709265ea71180f226d7))
* Use schema stuff in the capabilities instead of custom parsing ([#220](https://github.com/Le-Space/ucanto/issues/220)) ([8a578ae](https://github.com/Le-Space/ucanto/commit/8a578ae403f7270fc741f8aef07f1d3621fb29f9))
* validate attestation from another service ([#369](https://github.com/Le-Space/ucanto/issues/369)) ([bac2cb0](https://github.com/Le-Space/ucanto/commit/bac2cb08bd67de97ef6a7360713e4fd1d0ae1d5c)), closes [#267](https://github.com/Le-Space/ucanto/issues/267)
* wildcard support in capabilies ([#218](https://github.com/Le-Space/ucanto/issues/218)) ([545d9c2](https://github.com/Le-Space/ucanto/commit/545d9c25d9bd8000eaff4978432bc1bbba14654e))


### Bug Fixes

* add [@returns](https://github.com/returns) to @ucanto/validator Schema.dictionary() to avoid problematic inference when using derives ([#215](https://github.com/Le-Space/ucanto/issues/215)) ([620421d](https://github.com/Le-Space/ucanto/commit/620421d450a82d165301ae8d0ebad1ec041db636))
* add return type to URI.uri() schema ([#127](https://github.com/Le-Space/ucanto/issues/127)) ([c302866](https://github.com/Le-Space/ucanto/commit/c3028667bc1094e6f6b16c43b3a396ef6207f75c))
* build types before publishing ([#71](https://github.com/Le-Space/ucanto/issues/71)) ([04b7958](https://github.com/Le-Space/ucanto/commit/04b79588f77dba234aaf628f62f574b124bd540b))
* correct JSON syntax errors and missing workspace dependencies ([18ef65d](https://github.com/Le-Space/ucanto/commit/18ef65ddf642cd1c4da3e3819f869e00b315b007))
* downgrade versions ([#158](https://github.com/Le-Space/ucanto/issues/158)) ([f814e75](https://github.com/Le-Space/ucanto/commit/f814e75a89d3ed7c3488a8cb7af8d94f0cfba440))
* error messages on invalid proofs ([#187](https://github.com/Le-Space/ucanto/issues/187)) ([cb1a3bc](https://github.com/Le-Space/ucanto/commit/cb1a3bca9d51c95f369f28f1c2be46ee213ed053))
* exponential scan ([#329](https://github.com/Le-Space/ucanto/issues/329)) ([a81c8d5](https://github.com/Le-Space/ucanto/commit/a81c8d5d43c7da502504093d9d12e2c0d4619b2d))
* infinite recursion with unknown attestation ([#368](https://github.com/Le-Space/ucanto/issues/368)) ([d94496a](https://github.com/Le-Space/ucanto/commit/d94496a1aeabf21b8206a6e345fe6b7772b3d52a))
* intermittent test failures ([#166](https://github.com/Le-Space/ucanto/issues/166)) ([6cb0348](https://github.com/Le-Space/ucanto/commit/6cb03482bd257d2ea62b6558e1f6ee1a693b68fb))
* optional caveats ([#106](https://github.com/Le-Space/ucanto/issues/106)) ([537a4c8](https://github.com/Le-Space/ucanto/commit/537a4c86fdd02c26c1442d6a205e8977afbad603))
* optional field validation ([#124](https://github.com/Le-Space/ucanto/issues/124)) ([87b70d2](https://github.com/Le-Space/ucanto/commit/87b70d2d56c07f8257717fa5ef584a21eb0417c8))
* reconfigure release-please ([#230](https://github.com/Le-Space/ucanto/issues/230)) ([c16e100](https://github.com/Le-Space/ucanto/commit/c16e10004a5d9f3071f9bfe833e3888851fe4202))
* trigger interface upgrade for all packages ([#349](https://github.com/Le-Space/ucanto/issues/349)) ([255f0c1](https://github.com/Le-Space/ucanto/commit/255f0c1a7779ae9356e8f889e22b491a9789d334))
* trigger releases ([a0d9291](https://github.com/Le-Space/ucanto/commit/a0d9291f9e20456e115fa6c7890cafe937fa511e))
* update @ipld/car and @ipld/dag-cbor deps ([#120](https://github.com/Le-Space/ucanto/issues/120)) ([5dcd7a5](https://github.com/Le-Space/ucanto/commit/5dcd7a5788dfd126f332b126f7ad1215972f29c4))
* upgrade dependencies ([#366](https://github.com/Le-Space/ucanto/issues/366)) ([bf6274c](https://github.com/Le-Space/ucanto/commit/bf6274ce637bab6a97f38065cf6c2b7eb10e3c24))
* **validator:** resolve TypeScript literal type inference for error class names& ([df215a0](https://github.com/Le-Space/ucanto/commit/df215a089858eb28cf44a3d2240caf1e82be8615))
* versions ([#131](https://github.com/Le-Space/ucanto/issues/131)) ([88b87a7](https://github.com/Le-Space/ucanto/commit/88b87a7f3a32c02a22ddffcb8f38199445097133))


### Miscellaneous Chores

* release 0.0.1-beta ([d6c7e73](https://github.com/Le-Space/ucanto/commit/d6c7e73de56278e2f2c92c4a0e1a2709c92bcbf9))
* release 0.7.0 ([b3a441d](https://github.com/Le-Space/ucanto/commit/b3a441d4f3d85ab5ae3e2a0331dfacbdd038be23))
* release 4.0.2 ([e9e35df](https://github.com/Le-Space/ucanto/commit/e9e35dffeeb7e5b5e19627f791b66bbdd35d2d11))
* release 4.2.2 ([b92c345](https://github.com/Le-Space/ucanto/commit/b92c3455e0c34f2fc566d00422c19d11c03626f5))
* release 4.2.2 ([fdb5326](https://github.com/Le-Space/ucanto/commit/fdb53260ae2f54cdb8fd9973be5386b36c3af4d0))
* release 4.2.3 ([5dc8158](https://github.com/Le-Space/ucanto/commit/5dc8158341cd668304c94a4b83e1d9b9affae410))
* release 4.3.0 ([b53bf3d](https://github.com/Le-Space/ucanto/commit/b53bf3d9fb582006598aa02ae4c534dfcc68c189))
* release 4.3.1 ([5c76285](https://github.com/Le-Space/ucanto/commit/5c762859c53de307486a8cf5f7c517b24a66d0f4))
* release 4.3.3 ([12ea70b](https://github.com/Le-Space/ucanto/commit/12ea70bbb06d43f7b98017e229f1e1af0dc2fa50))
* release 4.3.4 ([baad652](https://github.com/Le-Space/ucanto/commit/baad652ff7d9760d58bbada161b293e653e6d20e))
* release 4.4.0 ([e47dbfc](https://github.com/Le-Space/ucanto/commit/e47dbfc04b8caa2e3024c960c556251fc5fd9df7))
* release 5.0.0 ([1f809a9](https://github.com/Le-Space/ucanto/commit/1f809a9d41494756e155ffb951864a8b26673642))
* release 7.0.0 ([84e5c48](https://github.com/Le-Space/ucanto/commit/84e5c48141abd9555acc3adc910b00caff36ac44))
* release 9.0.0 ([303cc44](https://github.com/Le-Space/ucanto/commit/303cc4429dfb6058ef152eacc50ca146d3546743))
</details>

---
This PR was generated with [Release Please](https://github.com/googleapis/release-please). See [documentation](https://github.com/googleapis/release-please#release-please).