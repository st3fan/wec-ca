
Project specific instructions:
 - When making changes that are related to the ACME protocol, read the ACME protocol specification at https://www.rfc-editor.org/rfc/rfc8555.txt
 - It is important that the code we write follows the RFC.

Version control specific changes:
 - Never commit changes directly to the main branch. Always do work on a feature branch.

Go tools instructions:
 - Always run `go vet` and `govulncheck` before committing code

Go programming instructions:
 - Try to use the standard library as much as possible
 - Prefer the standard http library over web frameworks like Gorilla
 - Logging is always structured logging in JSON format
 - Prefer small testable functions that can be called from methods.
 - Use CamelCase for exported functions/variablesAdd commentMore actions
 - Use camelCase for non-exported functions/variablesAdd comment

