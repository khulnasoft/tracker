# Cosign: verify tracker signature


## Prerequisites

Before you begin, ensure that you have the following installed:

- [cosign](https://docs.sigstore.dev/cosign/installation/)

## Verify tracker signature

Tracker images are signed with cosign keyless. To verify the signature we can run the command:

```console
cosign verify aquasec/tracker:tag-name  --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp https://github.com/khulnasoft/tracker | jq
```

Note that all of the tag-names can be found on the [Tracker Docker Hub Registry](https://hub.docker.com/r/aquasec/tracker/tags).

The output should look similar to the following:
![Tracker Signature Scanning](../images/signatures.png)
