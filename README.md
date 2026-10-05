# RenameCredentialBrokerApi

API service that brokers short-lived service-account credentials to trusted
client scripts, which then perform the privileged device rename **locally**
on the device itself — instead of having the server execute the rename
remotely.

## Status
🚧 Scaffolding in progress. Architecture and implementation details to follow.

## Background
This repository supersedes [`RenameApiService`](https://github.com/robgrame/RenameApiService),
which implemented a server-side remote-execution model (WinRM/JEA). The new
model inverts responsibility: the API only brokers a time-limited credential;
the calling script (`Monitor-HybridJoin-RenameReboot.ps1` or its successor)
performs `Rename-Computer` itself, using the brokered credential, directly on
the local machine.
