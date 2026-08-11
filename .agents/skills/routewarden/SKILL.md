---
name: routewarden
description: >-
  Diff-aware security auditor for Express, NestJS, and Next.js routes.
  Analyzes uncommitted git diffs for missing authentication (CWE-306) and sensitive response leakage (CWE-200).
---

# RouteWarden Security Audit Skill

Use this skill when writing, modifying, or reviewing web application routes in **Express**, **NestJS**, or **Next.js** (App Router and Pages Router).

---

## 1. Activation Triggers

Activate this skill when:
- **Creating or modifying API routes**: Adding or altering `POST`, `PUT`, `DELETE`, or `PATCH` endpoints in TypeScript/JavaScript.
- **Performing Code Reviews**: Reviewing pull requests or git diffs before committing code.
- **Explicit User Request**: When the user asks for a "route security check", "auth audit", or "RouteWarden scan".

---

## 2. Scope & Vulnerability Rules

### Rule A: HTTP Method Scope Differentiation
- **CWE-306 (Missing Authentication)**: Evaluated **ONLY** on mutable HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`). Read-only methods (`GET`, `HEAD`, `OPTIONS`) are **EXEMPT** from CWE-306 checks by default.
- **CWE-200 (Sensitive Response Leakage)**: Evaluated on **ALL** HTTP methods (including `GET` and `HEAD`). If a `GET` route payload contains sensitive keys (`password`, `token`, `secret`, `mock`, `bypass`, `private_key`), it MUST be flagged.

### Rule B: Exemptions for Public Routes
Route paths containing any of these public entry-point keywords (case-insensitive) are exempt from CWE-306 checks:
`login`, `logout`, `signin`, `signout`, `register`, `signup`, `forgot-password`, `password-reset`, `reset-password`, `refresh-token`.

---

## 3. Framework-Specific Guard Recognition Rules

### A. Express.js: Inline, Router-Level, and App-Level Middlewares
RouteWarden recognizes authentication in Express across 3 placement patterns:
1. **Inline per route**: `router.post("/path", authenticate, handler)`
2. **Router-level middleware**: `router.use(authenticate)` declared BEFORE the target route definition in the same file or parent router scope. All routes following `router.use(auth)` are considered **PROTECTED**.
3. **App-level middleware**: `app.use("/api", authenticate)` declared before mounting the router.

### B. NestJS: Controller-Level & Method-Level Guard Decorators
RouteWarden recognizes NestJS `@UseGuards(...)` in 2 placement patterns:
1. **Class-level Decorator**: `@UseGuards(JwtAuthGuard)` placed above the `@Controller(...)` class definition. Inherited by **ALL** route handler methods in the class.
2. **Method-level Decorator**: `@UseGuards(JwtAuthGuard)` placed above individual `@Post()`, `@Put()`, `@Delete()`, or `@Patch()` method declarations.

### C. Next.js App Router (`route.ts`) & Pages Router
RouteWarden recognizes Next.js authentication across 3 patterns:
1. **Body Call Checks**: Invoking `const session = await getServerSession(...)`, `const { userId } = await auth()`, or `requireAuth()` inside the `export async function POST(req)` handler body.
2. **Higher-Order Handler Wrappers**: Wrapping exported handlers with `export const POST = withAuth(async (req) => { ... })`.
3. **App Middleware**: Edge `middleware.ts` running `clerkMiddleware()` or `authMiddleware()`.

---

## 4. Catalog of Recognized Auth Middlewares & Guards

Below is the authoritative catalog derived from `rules.yaml`:

| Provider | Recognized Identifier / Pattern | Supported Syntax Patterns |
| :--- | :--- | :--- |
| **Clerk** | `clerkMiddleware`, `requireAuth`, `ClerkExpressRequireAuth`, `ClerkExpressWithAuth` | Middleware, Decorator, `auth()` call |
| **Supabase** | `requireSupabaseAuth`, `supabaseAuthMiddleware`, `withSupabaseAuth` | Middleware, Handler Wrapper |
| **Auth0** | `checkJwt`, `auth`, `requiresAuth` | Middleware, Decorator |
| **NextAuth** | `withAuth`, `getServerSession`, `authMiddleware` | Body Call, Wrapper, Middleware |
| **RealWorld** | `auth.required` | Express `router.use(auth.required)` |
| **Generic / Custom** | `authenticate`, `isAuthenticated`, `AuthGuard`, `JwtAuthGuard`, `requireLogin`, `protect` | Decorator `@UseGuards`, Chained Middleware |

---

## 5. Agent Execution Procedure

Run the following workflow:

```bash
# 1. Inspect uncommitted working tree modifications (staged + unstaged)
git diff HEAD

# 2. Inspect staged changes only (if applicable)
git diff --cached

# 3. Compare against branch (if specified by user)
git diff <branch>...HEAD
```

1. Identify modified TypeScript/JavaScript files containing routes.
2. For each added/modified route line (`+` in diff):
   - Determine HTTP method (`POST`/`PUT`/`DELETE`/`PATCH` vs `GET`/`HEAD`).
   - Check if path contains a public keyword (exempt from CWE-306).
   - Check for auth guards: inline middleware, router-level `use()`, class/method `@UseGuards()`, or body `getServerSession()` calls.
   - If mutable route lacks auth guard and is not public -> Flag **CWE-306 (High Risk)**.
   - Inspect returned response payload keys for sensitive names (`password`, `token`, `secret`, `mock`, `bypass`) -> Flag **CWE-200 (High Risk)**.

---

## 6. Expected Output Format

Report findings using the structured layout:

```markdown
### 🚨 RouteWarden Security Finding

- **File**: `path/to/file.ts` (Line XX)
- **Vulnerability**: `CWE-306: Missing Authentication for Critical Function` | `CWE-200: Exposure of Sensitive Information`
- **Severity**: HIGH
- **Code Snippet**:
  ```ts
  // Code snippet from diff
  ```
- **Reason**: Concise explanation of why this was flagged.
- **Remediation**:
  ```ts
  // Suggested fixed code snippet
  ```
```

---

## 7. Remediation Guide by Framework

### Express.js (Router-Level & Inline)
```ts
// ❌ FLAGGED (CWE-306)
router.post("/api/users", createUserHandler);

// ✅ REMEDIATED (Option A: Router-level)
router.use(authenticate);
router.post("/api/users", createUserHandler);

// ✅ REMEDIATED (Option B: Inline)
router.post("/api/users", authenticate, createUserHandler);
```

### NestJS (Class Guard & Method Guard)
```ts
// ❌ FLAGGED (CWE-306)
@Controller('orders')
export class OrdersController {
  @Post()
  createOrder() { ... }
}

// ✅ REMEDIATED (Option A: Class Decorator)
@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Post()
  createOrder() { ... }
}

// ✅ REMEDIATED (Option B: Method Decorator)
@Controller('orders')
export class OrdersController {
  @UseGuards(JwtAuthGuard)
  @Post()
  createOrder() { ... }
}
```

### Next.js App Router (`route.ts`)
```ts
// ❌ FLAGGED (CWE-200: Sensitive Field Leakage)
export async function POST(req: Request) {
  const user = await db.user.create(...);
  return NextResponse.json({ user, token: user.sessionToken, password: user.passwordHash });
}

// ✅ REMEDIATED (CWE-306 & CWE-200 Fix)
export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  
  const user = await db.user.create(...);
  return NextResponse.json({ id: user.id, email: user.email });
}
```
