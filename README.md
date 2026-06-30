# pgho_permissions

A PostgreSQL extension that brings flexible, hierarchical access control to your database. It supports both **role-based** (RBAC) and **action-based** (ABAC) permission models, and both **principals** (actors) and **resources** can be organized into parent→child hierarchies so that permissions cascade naturally without duplicating rules.

Built with Supabase in mind: all tables have RLS enabled, lookup functions run as `SECURITY DEFINER`, and the extension is installable via [database.dev](https://database.dev).

---

## Installation

Install via [database.dev](https://database.dev) (requires the `dbdev` utility):

```sql
-- Install the extension
SELECT dbdev.install('asghonim@pgho_permissions');

-- (Re)create the schema and extension
DROP EXTENSION  IF EXISTS "asghonim@pgho_permissions";
DROP SCHEMA     IF EXISTS pgho_permissions;
CREATE SCHEMA   IF NOT EXISTS pgho_permissions;
CREATE EXTENSION IF NOT EXISTS "asghonim@pgho_permissions"
  SCHEMA pgho_permissions
  VERSION '0.0.17';
```

You can substitute any schema name you prefer for `pgho_permissions`.

---

## Usage

### 1. Create roles and actions

```sql
-- Roles for RBAC checks
INSERT INTO pgho_permissions.roles (role_name) VALUES ('tenant_admin');
INSERT INTO pgho_permissions.roles (role_name) VALUES ('tenant_member');

-- Actions for fine-grained ABAC checks
INSERT INTO pgho_permissions.actions (action_name) VALUES ('read');
INSERT INTO pgho_permissions.actions (action_name) VALUES ('write');
INSERT INTO pgho_permissions.actions (action_name) VALUES ('delete');
```

### 2. Register principals automatically via trigger

Create a principal row whenever a new user is added to `auth.users`:

```sql
CREATE OR REPLACE FUNCTION private.on_auth_user_inserted()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO pgho_permissions.principals (principal_type, principal_uuid)
    VALUES ('user', NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_inserted
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION private.on_auth_user_inserted();
```

### 3. Register resources automatically via trigger

Create a resource row whenever a new tenant (or any protected entity) is inserted:

```sql
CREATE OR REPLACE FUNCTION private.on_tenant_inserted()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO pgho_permissions.resources (resource_type, resource_uuid)
    VALUES ('tenant', NEW.uid);
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_tenant_inserted
  AFTER INSERT ON public.tenants
  FOR EACH ROW EXECUTE FUNCTION private.on_tenant_inserted();
```

### 4. Grant a role to a user on a resource

```sql
INSERT INTO pgho_permissions.role_permissions (principal_id, role_id, resource_id)
VALUES (
    pgho_permissions.principal('user',   '<user-uuid>'),
    pgho_permissions.role('tenant_admin'),
    pgho_permissions.resource('tenant', '<tenant-uuid>')
);
```

### 5. Grant or deny a specific action

```sql
-- Explicitly allow a user to delete documents inside a project
INSERT INTO pgho_permissions.action_permissions (principal_id, action_id, resource_id, access)
VALUES (
    pgho_permissions.principal('user',    '<user-uuid>'),
    pgho_permissions.action('delete'),
    pgho_permissions.resource('project', '<project-uuid>'),
    'ALLOW'
);

-- Explicitly deny a user from writing to a specific document (overrides any parent ALLOW)
INSERT INTO pgho_permissions.action_permissions (principal_id, action_id, resource_id, access)
VALUES (
    pgho_permissions.principal('user',     '<user-uuid>'),
    pgho_permissions.action('write'),
    pgho_permissions.resource('document', '<document-uuid>'),
    'DENY'
);
```

### 6. Protect tables with RLS policies

Use `has_role_permission` or `has_action_permission` inside a `USING` clause:

```sql
-- RBAC: only tenant_admin may SELECT rows from public.tenants
CREATE POLICY "SELECT tenants"
  ON public.tenants
  FOR SELECT
  USING (
    pgho_permissions.has_role_permission(
      pgho_permissions.principal('user',   auth.uid()),
      pgho_permissions.role('tenant_admin'),
      pgho_permissions.resource('tenant', public.tenants.uid)
    )
  );
GRANT SELECT ON public.tenants TO authenticated;

-- ABAC: users may only SELECT documents they have explicit 'read' access to
CREATE POLICY "SELECT documents"
  ON public.documents
  FOR SELECT
  USING (
    pgho_permissions.has_action_permission(
      pgho_permissions.principal('user',     auth.uid()),
      pgho_permissions.action('read'),
      pgho_permissions.resource('document', public.documents.uid)
    )
  );
GRANT SELECT ON public.documents TO authenticated;
```

---

## Concepts

| Concept | What it represents | Example |
| --- | --- | --- |
| **Principal** | An actor that can hold permissions | `user`, `team`, `service_account` |
| **Resource** | A thing being protected | `tenant`, `project`, `document` |
| **Role** | A named capability assigned to a principal on a resource | `tenant_admin`, `viewer` |
| **Action** | A fine-grained operation that can be explicitly allowed or denied | `read`, `write`, `delete` |

### Roles and actions are opaque

The extension treats roles and actions as **plain names**. A role has no intrinsic meaning beyond its string identifier — the extension does not know what `tenant_admin` implies, whether roles subsume actions, or whether one role outranks another. The same is true for actions: `delete` is just a label.

All semantics are **application-defined**. Your RLS policies are the place where meaning is assigned:

```sql
-- The application decides that holding "tenant_admin" means you may SELECT tenants.
CREATE POLICY "SELECT tenants"
  ON public.tenants FOR SELECT
  USING (
    pgho_permissions.has_role_permission(
      pgho_permissions.principal('user', auth.uid()),
      pgho_permissions.role('tenant_admin'),
      pgho_permissions.resource('tenant', uid)
    )
  );

-- The application decides that holding "write" access to a document means you may UPDATE it.
CREATE POLICY "UPDATE documents"
  ON public.documents FOR UPDATE
  USING (
    pgho_permissions.has_action_permission(
      pgho_permissions.principal('user', auth.uid()),
      pgho_permissions.action('write'),
      pgho_permissions.resource('document', uid)
    )
  );
```

Whether a role implies certain actions, whether roles and actions coexist on the same resource, and how types like `user` or `tenant` map to your schema — all of that is up to you. The extension only answers "does this principal hold this role/action on this resource (or an ancestor)?"

The **relationship between roles and actions is also application-defined**. Your RLS policies can rely exclusively on roles, exclusively on actions, or combine both — and you control which check takes precedence:

```sql
-- Role-only: a tenant_admin may do anything on the tenant.
USING (has_role_permission(..., role('tenant_admin'), ...))

-- Action-only: access is gated on a fine-grained action check.
USING (has_action_permission(..., action('read'), ...))

-- Both: a role check is sufficient, but an explicit action grant also works.
USING (
  has_role_permission(..., role('tenant_admin'), ...)
  OR
  has_action_permission(..., action('read'), ...)
)

-- Role overrides action: admins bypass the action check entirely.
USING (
  has_role_permission(..., role('tenant_admin'), ...)
  OR (
    NOT has_role_permission(..., role('tenant_admin'), ...)
    AND has_action_permission(..., action('read'), ...)
  )
)
```

The extension enforces no ordering or interaction between the two — that logic lives in your policies.

### Hierarchies

Both principals and resources support a `parent_id` pointer for building trees:

```text
Organization (principal)
  └── Team (principal)
        └── User (principal)

Workspace (resource)
  └── Project (resource)
        └── Document (resource)
```

When checking a permission, the engine walks **up** both hierarchies. A rule defined on a parent resource or a parent principal is inherited by all children.

**Precedence** is determined first by principal specificity, then by resource specificity. A permission attached to a more specific principal always overrides one attached to an ancestor principal, regardless of resource specificity. Within the same principal, the most specific resource wins. If no rule is found anywhere, the result is **DENY**.

| Priority | Principal | Resource |
| --- | --- | --- |
| 1 | Exact | Exact |
| 2 | Exact | Parent |
| 3 | Exact | Grandparent … |
| 4 | Parent | Exact |
| 5 | Parent | Parent |
| 6 | Parent | Grandparent … |
| 7 | Grandparent | Exact |
| … | … | … |

This is the order the engine evaluates candidates: it exhausts the full resource hierarchy for the current principal before moving one level up the principal hierarchy.

---

## Architecture

### Tables

| Table | Purpose |
| --- | --- |
| `resources` | Registry of every protected object |
| `principals` | Registry of every actor |
| `roles` | Named roles (e.g. `admin`, `viewer`) |
| `actions` | Named actions (e.g. `read`, `write`) |
| `role_permissions` | Grants a role to a principal on a resource |
| `action_permissions` | Grants or denies an action for a principal on a resource (`ALLOW` / `DENY`) |
| `resource_closure` | Materialized ancestor/descendant pairs for the resource hierarchy |
| `principal_closure` | Materialized ancestor/descendant pairs for the principal hierarchy |

`resource_closure` and `principal_closure` are the performance foundation of the extension. Without them, resolving "does this resource inherit from that ancestor?" would require a recursive CTE or a loop — re-executing a query at each level of the hierarchy. With the closure tables, every ancestor-descendant pair is pre-written at insert/reparent time, so both `has_role_permission` and `has_action_permission` resolve the full hierarchy in a **single SQL statement with two index joins**, regardless of how deep the tree is.

The cost is on writes: triggers maintain both tables whenever a node is inserted, reparented, or deleted. For authorization workloads — where a single page load may trigger dozens of RLS checks but hierarchies change rarely — this trade-off is strongly in favour of fast reads.

### Functions

| Function | Returns | Description |
| --- | --- | --- |
| `principal(type, uuid)` | `BIGINT` | Looks up a principal's internal ID |
| `resource(type, uuid)` | `BIGINT` | Looks up a resource's internal ID |
| `role(name)` | `BIGINT` | Looks up a role's internal ID |
| `action(name)` | `BIGINT` | Looks up an action's internal ID |
| `has_role_permission(principal_id, role_id, resource_id)` | `BOOLEAN` | Checks if a principal holds a role on a resource (walks both hierarchies) |
| `has_action_permission(principal_id, action_id, resource_id)` | `BOOLEAN` | Checks if a principal is allowed an action on a resource (walks both hierarchies) |

### Permission resolution

Both `has_role_permission` and `has_action_permission` use the same two-level walk:

1. Start at the given principal; start at the given resource.
2. Look for a matching rule at (current principal, current resource).
3. If found → return its result immediately.
4. If not found → move one level up the **resource** hierarchy and repeat from step 2.
5. Once the resource hierarchy is exhausted → move one level up the **principal** hierarchy and restart the resource walk from step 2.
6. If the entire search space is exhausted → return `FALSE` (default deny).

---

## Common patterns

### Multi-tenant SaaS

Register each tenant as a **resource** and each user as a **principal**. Grant a `tenant_admin` role to the tenant owner on tenant creation:

```sql
-- After creating the tenant and the resource row
INSERT INTO pgho_permissions.role_permissions (principal_id, role_id, resource_id)
SELECT
    pgho_permissions.principal('user',   owner_user_id),
    pgho_permissions.role('tenant_admin'),
    pgho_permissions.resource('tenant', NEW.uid)
FROM public.tenants
WHERE uid = '<new-tenant-uuid>';
```

### Hierarchical resources (org → project → document)

Register all three levels as resources with `parent_id` set:

```sql
-- Insert project as a child of its org
INSERT INTO pgho_permissions.resources (resource_type, resource_uuid, parent_id)
VALUES (
    'project',
    '<project-uuid>',
    pgho_permissions.resource('org', '<org-uuid>')
);

-- Insert document as a child of its project
INSERT INTO pgho_permissions.resources (resource_type, resource_uuid, parent_id)
VALUES (
    'document',
    '<doc-uuid>',
    pgho_permissions.resource('project', '<project-uuid>')
);
```

A permission granted on the org now automatically covers all projects and documents beneath it — no extra rows needed.

### Granting permissions across all resources (root resource)

Suppose you want to give an admin `OWNER` on *every* resource — across every tenant, project, and document — without touching each row individually.

The idiomatic solution is to make every resource hierarchy rooted at a single synthetic **root resource**. The root is a normal row in `resources`; it just has no `parent_id` and no corresponding domain object.

```sql
-- Create the root resource once (no resource_uuid needed)
INSERT INTO pgho_permissions.resources (resource_type, resource_uuid, parent_id)
VALUES ('root', NULL, NULL);
```

Every other top-level resource then becomes a child of root:

```sql
-- Tenant A hangs off the root
INSERT INTO pgho_permissions.resources (resource_type, resource_uuid, parent_id)
VALUES ('tenant', '<tenant-a-uuid>', pgho_permissions.resource('root', NULL));
```

This gives you a single tree that looks like:

```text
root
├── Tenant A
│   ├── Project 1
│   │   └── Document 1
│   └── Project 2
└── Tenant B
    └── Project 3
```

To grant a principal `OWNER` everywhere:

```sql
INSERT INTO pgho_permissions.role_permissions (principal_id, role_id, resource_id)
VALUES (
    pgho_permissions.principal('user',  '<admin-uuid>'),
    pgho_permissions.role('owner'),
    pgho_permissions.resource('root', NULL)
);
```

No special code. The hierarchy walk already climbs from any document → project → tenant → root, so the rule is found naturally.

#### How the walk reaches it

`has_role_permission(Bob, OWNER, Document 1)` walks:

```text
Document 1 → Project 1 → Tenant A → root   ← rule found here
```

Exactly as today. Nothing changes.

#### Category roots (scoped global grants)

You can introduce intermediate synthetic roots to scope a global grant to one resource type without affecting others:

```sql
-- A synthetic node that groups all projects
INSERT INTO pgho_permissions.resources (resource_type, resource_uuid, parent_id)
VALUES ('projects_root', NULL, pgho_permissions.resource('root', NULL));

-- All projects hang off it
UPDATE pgho_permissions.resources
SET parent_id = pgho_permissions.resource('projects_root', NULL)
WHERE resource_type = 'project';
```

Now `EDITOR` on `projects_root` covers every project but not tenants, invoices, or anything else.

#### Multiple independent trees

If your application has resource types that are unrelated (tenants, invoices, products), introduce one shared root and attach each unrelated tree to it:

```text
root
├── Tenants
├── Invoices
├── Products
└── Reports
```

Every top-level resource attaches somewhere, and a single grant on root still reaches all of them via the ordinary ancestor walk.

### Group / team membership

Create teams as principals with `parent_id` pointing to the org principal, then add users as children of the team:

```sql
-- Register a team
INSERT INTO pgho_permissions.principals (principal_type, principal_uuid, parent_id)
VALUES (
    'team',
    '<team-uuid>',
    pgho_permissions.principal('org', '<org-uuid>')
);

-- Add a user to the team
UPDATE pgho_permissions.principals
SET parent_id = pgho_permissions.principal('team', '<team-uuid>')
WHERE principal_type = 'user' AND principal_uuid = '<user-uuid>';
```

A role granted to the team is now automatically inherited by all its member users.

---

## Design philosophy

This extension is intentionally narrow. It does not attempt to replicate cloud IAM systems (like AWS IAM) or distributed authorization engines (like Google Zanzibar). Those systems solve real problems — cross-service policy propagation, planet-scale consistency, attribute-based conditions — but they carry significant operational weight: separate infrastructure, network round-trips on every check, and policy languages with steep learning curves.

**AWS IAM** is designed for controlling access to cloud infrastructure across dozens of independent services. It ships with a large set of primitives (policies, permission boundaries, SCPs, resource-based policies) that interact in non-obvious ways. Replicating that model inside a Postgres extension would introduce the same accidental complexity without the underlying cloud services that justify it.

**Zanzibar** (and systems modelled on it, like SpiceDB or OpenFGA) materialises a global permission graph that can be queried at low latency regardless of data size. The trade-off is a separate service that must be kept in sync with your application database. Every write that affects permissions now has two targets; any drift between them is a correctness bug.

This extension takes a different bet: **your Postgres database is already the source of truth, so keep authorization there too.** The entire permission graph lives in the same ACID transaction as your application data. A permission grant and the row it protects are written atomically, checked by the query planner, and backed up together. There is no sync gap.

The scope is deliberately limited to what a relational database does well:

- Hierarchical principals and resources, resolved at query time via materialized closure tables.
- Role checks (`has_role_permission`) and allow/deny action checks (`has_action_permission`), callable directly from RLS policies.
- No built-in policy language — semantics live in your SQL, which is already the language your team reads and reviews.

If your application eventually outgrows a single Postgres cluster, or needs cross-service authorization that spans infrastructure outside the database, a dedicated authorization service becomes the right tool. Until then, the simpler system is usually the better one.

---

## Security notes

- All permission tables have **Row Level Security enabled**. Only `service_role` has direct table access; normal application roles should go through the `SECURITY DEFINER` functions.
- The lookup functions (`principal`, `resource`, `role`) and the check functions (`has_role_permission`, `has_action_permission`) all run as `SECURITY DEFINER` to prevent bypassing RLS at the permission layer itself.
- Permission checks default to **DENY** — a missing rule never grants access.
