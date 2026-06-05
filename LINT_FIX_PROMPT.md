# Golangci-lint Batch Fix Prompt

**Your task is to fix golangci-lint issues batch by batch in this repo.**

## Workflow

1. **Run golangci-lint and select next batch of 50 issues**
   - Group by: same file > same linter rule > order of appearance
   - Skip if conflicts with current branch work
   
2. **Fix the issues** following error handling standards (below)
   - **IMPORTANT: For each function call where you add error handling, check if all users of the function already log the error. If they do, remove the logging from that function first.**
   
3. **Verify fixes:**
   - Run golangci-lint to confirm issues resolved
   - Run relevant tests if available
   - Run `E2E_NO_REBUILD= make test-e2e` and check the logs to make sure you won't get excessive logs (more than 3+) from changed codes. 
   
4. **Spawn sub-agent for code review**
   
5. **Address review comments** (max 5 rounds)
   - If >5 rounds needed, notify user to intervene
   
6. **Commit when reviewer approves** (no critical issues)
   - Commit message: `fix(lint): resolve [linter-rule] in [file/area]`
   
7. **STOP and report progress**
   - After completing ONE batch (~20 issues), STOP immediately

## Error Handling Standards

### General Principles

1. **Never use //nolint** to suppress issues

2. **Always propagate errors via function signatures**
   - If the function prototype doesn't return an error, you must attempt to change it to propagate errors to caller.
   - Always add comment if it's not possible.

3. **Wrap errors with context using %w**
   - Wrap with context: `fmt.Errorf("failed to parse port %q: %w", port, err)`
   - Preserve error chain with %w

4. **Never use blank identifier `_` for error returns**
   - This project has `errcheck.check-blank: true` in .golangci.yml
   - Using `_` to ignore errors will fail the linter
   - You MUST handle the error properly by either returning it to caller or logging it or both.

5. **Name error variables must be named `err` by default**
   - Always reuse the `err` already exists.
   - Only when both errors must be kept, you can use a different name.

6. **Prevent duplicate logging** (see detailed examples below)
   - When returning errors to caller, do not log in the function
   - Before adding error handling, check if called functions already log the error
   - If they do, remove the log statement from those functions

### Choosing Log Level

- **Default: Warn** - Use for most error cases
- **Error** - Only for critical failures (goroutine crashes, unrecoverable states)
- **Debug** - For high-frequency errors (>60/min) or advisory/ignorable errors
- **Always add comment if not using Warn**: `// Log error: this is critical`

### Error Handling by Context

**Regular functions:**
- Return errors, don't log
- ❌ BAD: `log.Error(err); return err` (logs every stack frame)
- ✅ GOOD: `return fmt.Errorf("context: %w", err)` (log once at top)

**Main/init level:**
- CLI tools: log at Warn level: `log.WithError(err).Warn("something wrong")`
- Libraries: return error to caller

**HTTP handlers:**
- Log real error: `log.WithError(err).Warn("Failed to process request")`
- Return HTTP status code, generic message to client
- Don't expose internal error details in HTTP response

**Goroutine top-level:**
- Log at Warn level by default: `log.WithError(err).Warn("Goroutine failed")`
- Use Error level only if critical: `log.WithError(err).Error("Critical worker crashed")`
- Add comment explaining WHY: `// Log error: this is the top of goroutine`
- Include context about which goroutine/operation

**Test code:**
- Use `"github.com/stretchr/testify/require".NoError()` whenever possible
- If testify not possible, add comment: `// testify doesn't work because`

### Special Cases

**High-frequency errors:**
- Add comment explaining WHY: `// Suppress error: this can happen frequently`
- Use Debug-level logging: `log.WithError(err).Debug("operation failed")`

### Preventing Duplicate Logging

Before adding error handling, check if the function being called already logs the error. If it does, you MUST assign the error to a variable but NOT log it again (to avoid duplicate logging).

Example:
```go
// ❌ WRONG - Double logging
// In share/utils/helpers.go
func ParseConfig(path string) error {
    if err := readFile(path); err != nil {
        log.Error(err)  // ❌ Logs here
        return err      // AND returns
    }
}
// In main.go
if err := ParseConfig("config.yaml"); err != nil {
    log.Fatal(err)  // ❌ Logs again!
}

// ✅ CORRECT - Single logging point
// In share/utils/helpers.go
func ParseConfig(path string) error {
    if err := readFile(path); err != nil {
        return fmt.Errorf("failed to read config: %w", err)  // ✅ Just return
    }
}
// In main.go
if err := ParseConfig("config.yaml"); err != nil {
    log.Fatal(err)  // ✅ Log once at top level
}

// ✅ ALSO CORRECT - When called function already logs internally
// In worker.go
func doWork() (error, error) {
    // ... does work ...
    if criticalErr != nil {
        log.Error(criticalErr)  // Already logs here
    }
    return criticalErr, debugErr
}
// In main.go - MUST assign error even if already logged
if err, dbgErr := doWork(); err != nil || dbgErr != nil {
    // err is already logged inside doWork, no need to log again
    if dbgErr != nil {
        log.Debug(dbgErr)  // Only log the debug error
    }
}

// ❌ WRONG - Using blank identifier with check-blank: true
if _, dbgErr := doWork(); dbgErr != nil {  // ❌ Fails lint: check-blank: true
    log.Debug(dbgErr)
}
```

## Reviewer Checklist

✓ No critical issues (correctness, security, bugs)
✓ Appropriate log level (Warn default, Error for critical, Debug for high-frequency)
✓ **Any non-warning log level must have explanatory comment**
✓ The error is returned to the caller whenever possible.
✓ **Any errors not returned to caller must have explanatory comment**
✓ Error handling appropriate for context  
✓ Error messages have sufficient debugging context  
✓ **Log frequency check:** Could this error path trigger >60 times/min?  
  - Check: loops, retries, per-request handlers, polling intervals
  - If high-frequency, use Debug level. Do not implement a rate limiter for now.
✓ No unintended behavior changes  
✓ Wrapped errors preserve context with %w
✓ Extra logs removed when error is returned to caller
✓ **No duplicate logs in called functions** - if called functions already log the same error and all its callers have handled the error, the log in called functions should be removed.
✓ Error variables named `err` unless both errors have to be kept.

## User Intervention Needed When

- Review exceeds 5 rounds
- Log frequency could exceed 60/min
- Requires API changes affecting many callers  
- Uncertain if error can be safely ignored
- Cannot determine appropriate error handling level
- Cannot determine a way to handle an error
