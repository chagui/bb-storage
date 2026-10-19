# Prebuilt images for cdc support

This repository is identical to upstream buildbarn with the addition
that it publishes images with cdc support. This is not intended to be a
long term solution but rather a way to allow there to be two tracks of
buildbarn for a short period of time.

Switching to cdc support is a breaking change and while there is a
translation layer to support backwards compatibility this would require
routing to be configured such that all cdc-unaware components pass via a
frontend. As this may not be the way many cluster operators have set up
their cluster this means that upgrading the cluster piecemeal (component
by component) is unlikely to function correctly.

## Before you start

Read the proto files to understand the configuration schema of the cdc
support.

Notable changes:
 * There is no longer such a thing as a standalone replicator container,
   as it's not necessary in a cdc world.
 * The Content Addressable Storage (CAS) is now not a blob access
   configuration, but rather a compound object that contains the
   configuration for a CS and CMS.
 * The zstd pool is only used for decoding incoming streams and does not
   need to be configured for any other usage.

