---
title: TRACKER-REGO
section: 1
header: Tracker Rego Flag Manual
date: 2024/06
...

## NAME

tracker **\-\-rego** - Rego configurations

## SYNOPSIS

tracker **\-\-rego** <config-option\>

## DESCRIPTION

The **\-\-rego** flag allows you to configure rego settings for Tracker.

Possible configuration options:

- **partial-eval**: Enable partial evaluation of rego signatures.
- **aio**: Compile rego signatures altogether as an aggregate policy. By default, each signature is compiled separately.

## EXAMPLES

- To enable partial evaluation, use the following flag:

  ```console
  --rego partial-eval
  ```

- To enable partial evaluation and aggregate policy compilation, use the following flags:

  ```console
  --rego partial-eval --rego aio
  ```

Please refer to the [documentation](../events/custom/rego.md) for more information on rego signatures.
