# Design

## Goal

Build a small, legible action-review layer that sits between an agent and its tools. The layer decides whether each tool call is allowed, denied, or sent for human approval, and writes an audit record for every decision.

The point is not to build another agent framework. The point is to make the review decision explicit, testable and observable.

## Non-goals

- Production identity, authentication or authorization
- Real money movement, email delivery or network access
- A full policy language with formal verification
- A multi-tenant control plane
- A user interface

## Threat model

| Threat | Example | Control |
|---|---|---|
| Prompt injection | A web page tells the agent to email a secret to an attacker | Tool-call review checks the recipient domain before the email is sent |
| Over-permissioned tool call | The agent calls a tool with broader arguments than the task needs | Policy rules inspect tool arguments and the action context |
| Data exfiltration | The agent sends internal data to an external address | Domain allowlist on outbound email and fetch actions |
| Path escape | The agent reads `../../etc/passwd` or `/etc/passwd` | `path_escape` policy check, a sandbox resolver, `O_NOFOLLOW` and a multiply-linked-file check |
| Irreversible action | A transfer or deletion that cannot be undone | Human approval for actions marked irreversible |
| Confused deputy | A low-privilege user asks the agent to act with the agent's credentials | The action carries the user and context for future scope checks |

The current prototype covers the first five at a basic level. The confused-deputy case is represented in the action model but not enforced yet.

## Action lifecycle

1. The agent proposes a tool call.
2. The review layer builds an `Action` with the tool name, arguments, user, context, and the reversibility and impact declared in tool metadata. It snapshots the arguments before evaluation.
3. The policy engine evaluates the snapshot and returns `allow`, `deny` or `require_approval`.
4. If approval is required, the approver receives a copy and decides. A denied approval becomes a final deny. Mutating the copy cannot change the evaluated arguments.
5. The tool body runs only when the final decision is allow.
6. The audit logger records the evaluated snapshot, policy decision, final decision, rule, reason, approver identity, denial identity, error and latency.
7. The tool result returns to the agent.

## Policy model

A policy is a YAML file with a version, a default decision and an ordered list of rules.

```yaml
version: 1
default_decision: allow
rules:
  - name: deny_external_email
    decision: deny
    tool: send_email
    when:
      args.to:
        not_domain: example.com
    reason: Email to an external domain is not allowed without review.
```

A rule can scope to a tool and can carry a `when` mapping. The keys of `when` are dotted paths into the action. Supported roots are `tool`, `user`, `reversible`, `impact`, `args.<name>` and `context.<key>`.

Each condition is either a scalar equality check or a mapping of operators. All conditions in a rule must match. The loader rejects unknown keys, unknown operators, duplicate YAML keys, duplicate rule names, empty tool scopes, malformed paths, null scalar conditions, non-finite thresholds and unsupported versions. A policy that does not parse is an error, not a silent default to allow.

| Operator | Meaning |
|---|---|
| `eq`, `neq` | Type-strict equality and inequality; a boolean does not equal `1`, and a string does not equal `False` |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison; non-finite values and thresholds are rejected |
| `in`, `not_in` | Membership in a list, with the same type-strict comparison as `eq` |
| `contains`, `not_contains` | Substring check on strings; type-strict membership in lists |
| `domain`, `not_domain` | Compare every email address or URL host in a field with a domain |
| `path_prefix`, `not_path_prefix` | Normalised path prefix check on a segment boundary |
| `path_escape` | Whether a path is a non-string, absolute, contains a `..` component, or otherwise escapes |
| `exists` | Whether a value is present |

For a recipient list, `domain` matches only when every address is in the domain. `not_domain` matches when any address is outside it, so a mixed list cannot pass the rule. Display names are parsed, and ambiguous or unparsable URL forms fail the rule rather than being coerced to a hostname.

A missing value does not match any operator except `exists: false`. A scalar null condition is rejected at load time.

## Decision precedence

Rules are evaluated in order. The first matching rule wins. If no rule matches, `default_decision` applies.

Policy evaluation, approval and audit writing all fail closed. An exception in any path becomes a final deny, and the audit record carries a redacted error. The same applies when the approver returns something other than an `Approval`, a non-boolean decision or an empty identity, including an un-awaited coroutine.

This is deliberately simple. It makes the policy readable and easy to test. A production policy engine would likely need rule composition, priority levels, explicit conflict detection and a default-deny posture.

## Audit schema

Each audit record is one JSON line:

| Field | Meaning |
|---|---|
| `timestamp` | UTC ISO timestamp |
| `tool` | Tool name |
| `args` | Tool arguments, with secret-bearing values redacted and non-string keys normalised |
| `args_redacted` | Whether any argument value was redacted or normalised |
| `user` | User on whose behalf the agent is acting |
| `reversible` | Whether the action can be undone |
| `impact` | Low, medium or high |
| `policy_decision` | Allow, deny or require_approval from the policy |
| `final_decision` | Allow or deny after any human approval |
| `rule` | Matching rule name, or null |
| `reason` | Human-readable reason |
| `approved_by` | Identity that approved, or null |
| `denied_by` | Identity that denied an approval request, or null |
| `error` | Policy, approval or audit error, or null |
| `policy_latency_ms` | Time spent in policy evaluation |
| `approval_latency_ms` | Time spent waiting for human approval |

Redaction is key-name based and best-effort: a value under a name such as `body`, `password`, `token`, `secret` or `authorization` is replaced with a length marker, including nested dicts and lists. The same known values are removed from the free-form `reason` and `error` text, and the terminal approval prompt shows the redacted arguments. Values shorter than four characters are left in free-form text, because replacing them would corrupt the surrounding prose; argument values are redacted regardless of length. Non-finite floats and lone surrogates are made strict-JSON-safe so the log cannot fail on serialisation.

## Eval methodology

The eval harness uses labeled actions with an expected policy decision. It measures:

- Accuracy
- False positives: an action allowed when the label says deny
- False negatives: an action denied when the label says allow
- Approval bypasses: an action allowed when the label says require approval
- Unexpected approvals: an action sent for approval when the label says allow
- Rule mismatches: the expected rule did not fire
- Evaluation errors
- Approval-required cases

Each scenario may name the rule that must fire, and the loader rejects undeclared tools and unknown tool arguments. The eval harness tests the policy decision and rule selection, not the human approval step. The review layer tests cover the approval path separately.

The scenarios are synthetic. They are designed to exercise the policy surface, not to estimate real-world attack rates.

## Production gaps

- Identity and authentication
- OAuth scopes and token lifecycle
- MCP proxy integration
- Cumulative risk across a multi-step plan
- Policy composition and conflict detection
- A separate control plane with its own availability and latency budget
- Durable audit storage and tamper evidence
- Data classification for audit redaction beyond key-name matching
- Kernel-level sandbox confinement; the current resolver has a residual TOCTOU window
- Red-team coverage beyond the synthetic scenarios

## Open questions

- Should unknown tools default to deny or require approval?
- How should cumulative risk be represented across a run?
- Should policy decisions be signed and stored immutably?
- How should approval delegation work?
- What is the right latency budget for an inline review layer?
