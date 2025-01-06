I really don't have time to maintain this library further. If you want to fork it or use it despite lack of maintenance, feel free to clone locally and revert one commit.

This externally-maintained fork looks good though I did not personally write it so can't vouch for security: https://github.com/primal100/pybitcointools

## Overview

This repository is a Python project. It includes patterns to ignore Python bytecode files (`*.pyc`) and swap files (`*.swp`).

The purpose of this project is to provide tools for working with Bitcoin in Python.

For more information on rate limits and tokens, visit: http://www.blockcypher.com/dev/bitcoin#rate-limits-and-tokens

## Rate Limits and Tokens

This section provides usage instructions for the `blockcypher.py` module, which handles rate limits and tokens for BlockCypher's Bitcoin API.

### Usage Instructions

1. Import the `blockcypher` module:
    ```python
    import blockcypher
    ```

2. Set your API token:
    ```python
    blockcypher.set_api_token('your_api_token_here')
    ```

3. Retrieve the current API token:
    ```python
    token = blockcypher.get_api_token()
    print(f'Current API Token: {token}')
    ```

4. Check the current rate limit status:
    ```python
    rate_limit_status = blockcypher.get_rate_limit_status()
    print(f'Rate Limit Status: {rate_limit_status}')
    ```

For more information on rate limits and tokens, visit: http://www.blockcypher.com/dev/bitcoin#rate-limits-and-tokens
