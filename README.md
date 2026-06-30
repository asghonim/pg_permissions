# pgho_permissions

A PostgreSQL extension that brings flexible, hierarchical access control to your database. It supports both **role-based** (RBAC) and **action-based** (ABAC) permission models, and both **principals** (actors) and **resources** can be organized into parent→child hierarchies so that permissions cascade naturally without duplicating rules.

Built with Supabase in mind: all tables have RLS enabled, lookup functions run as `SECURITY DEFINER`, and the extension is installable via [database.dev](https://database.dev).

---

## Concepts

| Concept | What it represents | Example |
| --- | --- | --- |
| **Principal** | An actor that can hold permissions | `user`, `team`, `service_account` |
| **Resource** | A thing being protected | `tenant`, `project`, `document` |
| **Role** | A named capability assigned to a principal on a resource | `tenant_admin`, `viewer` |
| **Action** | A fine-grained operation that can be explicitly allowed or denied | `read`, `write`, `delete` |

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

## Security notes

- All permission tables have **Row Level Security enabled**. Only `service_role` has direct table access; normal application roles should go through the `SECURITY DEFINER` functions.
- The lookup functions (`principal`, `resource`, `role`) and the check functions (`has_role_permission`, `has_action_permission`) all run as `SECURITY DEFINER` to prevent bypassing RLS at the permission layer itself.
- Permission checks default to **DENY** — a missing rule never grants access.
