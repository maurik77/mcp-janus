---
  name: new-test
  description: Generate a table-driven Go test for a given function following the mcp-janus testify pattern.
  user-invocable: false
  ---

  Generate a table-driven test function following the patterns in internal/service/auth/impl_test.go:
  - Use testify/assert and testify/require (never testing.T.Error directly)
  - Group test cases in a `tests := []struct{...}{}` slice
  - Use descriptive `name` field for each case
  - Mock dependencies via local structs implementing the relevant interface
  - For JWT/token tests, reuse the testRSAKey() and signTestJWT() helpers if available

  Arguments: $ARGUMENTS — the function name or description of what to test.