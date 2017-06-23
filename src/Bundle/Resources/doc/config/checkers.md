Checkers
========

Checkers will verify claims and headers key/value of all JWSInterface objects.

Each Checker you create is available as a service you can inject in your own services or use from the container.
It will check the claims in the payload (if any) and headers you explicitly defined.

In the following example, we create a checker that will be available through `jose.encrypter.CHECKER1`:

```yml
jose:
    checkers:
        CHECKER1: # ID of the Signer. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            claim_checkers: # This checker will check the following claims (see below for the complete list)
                - 'exp' # Expiration claim
                - 'iat' # Issued at claim
                - 'nbf' # Not Before claim
            header_checkers: # This checker will check the following headers (see below for the complete list)
                - 'crit' # Critical header
```

# Supported Claim and Header Checkers

Hereafter the list of all checkers supported by this library.

You may need to check additional claims or headers, then [read that page](../next/custom_checker.md) to know how to create custom checkers.

# Supported Claim Checkers

* [x] `exp`
* [x] `iat`
* [x] `nbf`

# Supported Header Checkers

* [x] `crit`
