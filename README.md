# opnsense-ipsec-converter

#### Table of Contents

1. [Overview](#overview)
1. [Usage](#usage)
1. [Contributing](#contributing)

## Overview

OPNsense introduced a new IPsec GUI and will end support for the legacy IPsec GUI in release 26.1.

Migration from the old to the new GUI has to be done manually, which may be a pretty time-consuming (and error-prone) task.

This script tries to convert legacy IPsec configurations to the new format. It should work pretty well for simple configurations that rely (mostly) on default values. More complex configurations may required further adjustements to the script.

## Usage

WARNING: First perform a full backup of OPNsense. Run this migration in a test environment to ensure that it is working as expected!

Get a config backup from OPNsense, save it as `config.old.xml` and run the script:

```shell
$ ./ipsec.py
Reading full configuration from 'config.old.xml'...
Starting conversion of Phase 1 to <Connection>...
  - Phase 1 (ikeid: 3) -> Connection (uuid: 5fee7785-7f6e-408b-b012-69ccdf930a43) converted.

Starting conversion of Phase 2 to <child>...
  - Phase 2 (ikeid: 3, uniqid: 5d541916220aa) -> child (uuid: d6c63e89-2e50-45fe-b6c8-d91b89045866) converted.
    - SPD entry created for Child da4ddda6-4e5f-4925-9545-c94b65fa6e9c.
  - Phase 2 (ikeid: 3, uniqid: 5d59cd922d2c1) -> child (uuid: da4ddda6-4e5f-4925-9545-c94b65fa6e9c) converted.
  - Phase 2 (ikeid: 3, uniqid: 5d59cdb7a1d43) -> child (uuid: 6e0c0026-8125-4858-94b6-0ea59e5a0158) converted.

Conversion complete.
Found pre-shared keys to migrate. Updating <preSharedKeys> block.
  - Successfully replaced existing <preSharedKeys> block.
Found existing <Swanctl> block. Replacing it.
Saving format-preserved configuration to 'config.new.xml'...
Save successful.
```

It is highly recommended to verify the results:

```shell
$ diff -Naur config.old.xml config.new.xml
```

If the configuration looks good, try to replace the existing OPNsense configuration with the new one. Then navigate to `VPN: IPsec: Connections` and verify that everything is properly configured. You should disable the legacy IPsec configuration (`VPN: IPsec: Tunnel Settings`) and afterwards enable/apply the new IPsec configuration.

## Contributing

Fork and send a Pull Request. Thanks!
