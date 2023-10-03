# Optimistic Spartan verifier for the EVM

## Run tests
```
cargo test
```


## Run tests in debug mode
```
DEBUG=true cargo test
```
When `DEBUG=true`, the Ethereum JSONRpc provider will point to "http://localhost:8545". There must be an Ethereum node (Hardhat, Anvil, etc) running at that address. Debug mode exists because a standalone node is compatible console-logging and provides better error messages than an in-program Anvil instance.