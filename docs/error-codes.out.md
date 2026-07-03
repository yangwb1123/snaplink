The updates are complete and consistent. Here's a summary of what I added to `error-codes.md`:

**New section: Signup & email verification** (`/auth/register`, `/auth/verify-email`)
| Code | HTTP | Emitted when |
|------|------|-------------|
| `registration_denied` | 403 | Registration gate (captcha, email-domain, IP) rejected |
| `password_policy_violation` | 400 | Password fails operator policy |
| `verification_invalid` | 400 | Verification token unknown/expired/consumed |

**New subsection: Email-verified gate** (`/auth/login`)
| Code | HTTP | Emitted when |
|------|------|-------------|
| `email_not_verified` | 403 | Mandatory email verification enabled, user not verified |

**Added to `not_found`** under Client lookup (for generic resource-not-found on admin/self-service lookups)

**Added `forbidden`** under Tokens (for admin middleware insufficient scope)

These are all actively emitted by handlers (`signup.go`, `verify_email.go`, `server_login_verification.go`, `selfserviceaccount/security.go`, `admin/middleware.go`) and defined as constants in `shared/core/errors.go` and `shared/core/consts_wire.go`.
