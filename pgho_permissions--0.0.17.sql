CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -- UUID v7: time-ordered, sortable, suitable as a secondary unique identifier
CREATE OR REPLACE FUNCTION @extschema@.gen_uuid_v7()
RETURNS uuid AS $$
DECLARE
    unix_ts_ms bigint;
    uuid_bytes bytea;
BEGIN
    unix_ts_ms := (extract(epoch from clock_timestamp()) * 1000)::bigint;
    uuid_bytes := decode(lpad(to_hex(unix_ts_ms), 12, '0'), 'hex') ||
                  extensions.gen_random_bytes(10);
    uuid_bytes := set_byte(uuid_bytes, 6, (get_byte(uuid_bytes, 6) & 0x0f) | 0x70);
    uuid_bytes := set_byte(uuid_bytes, 8, (get_byte(uuid_bytes, 8) & 0x3f) | 0x80);
    RETURN encode(uuid_bytes, 'hex')::uuid;
END;
$$ LANGUAGE plpgsql VOLATILE SET search_path = '';

-- ---------------------------------------------------------------------------
-- Resources
-- Polymorphic resource registry with parent→child hierarchy.
-- Only resources that participate in hierarchy or need explicit ACL entries
-- need a row here; all other records are addressed by type + their own PK.
--   e.g. (resource_type='project', resource_uuid='uuid', parent_id → org row)
-- ---------------------------------------------------------------------------
CREATE TABLE @extschema@.resources (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    resource_type    TEXT        NOT NULL CHECK (char_length(resource_type) BETWEEN 1 AND 100),
    resource_uuid    UUID,
    parent_id        BIGINT      REFERENCES @extschema@.resources(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_type, resource_uuid)
    );
CREATE INDEX idx_resources_type_uuid ON @extschema@.resources(resource_type, resource_uuid);
CREATE INDEX idx_resources_parent ON @extschema@.resources(parent_id) WHERE parent_id IS NOT NULL;
ALTER TABLE @extschema@.resources ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.resources TO service_role;

CREATE TABLE @extschema@.principals (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    principal_type   TEXT        NOT NULL CHECK (char_length(principal_type) BETWEEN 1 AND 100),
    principal_uuid   UUID,
    parent_id        BIGINT      REFERENCES @extschema@.principals(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (principal_type, principal_uuid)
    );
CREATE INDEX idx_principals_type_uuid ON @extschema@.principals(principal_type, principal_uuid);
CREATE INDEX idx_principals_parent ON @extschema@.principals(parent_id) WHERE parent_id IS NOT NULL;
ALTER TABLE @extschema@.principals ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.principals TO service_role;

CREATE TABLE @extschema@.roles (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    role_name        TEXT        NOT NULL CHECK (char_length(role_name) BETWEEN 1 AND 100),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (role_name)
    );
CREATE INDEX idx_roles_name ON @extschema@.roles(role_name);
ALTER TABLE @extschema@.roles ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.roles TO service_role;

CREATE TABLE @extschema@.actions (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    action_name      TEXT        NOT NULL CHECK (char_length(action_name) BETWEEN 1 AND 100),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (action_name)
    );
CREATE INDEX idx_actions_name ON @extschema@.actions(action_name);
ALTER TABLE @extschema@.actions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.actions TO service_role;

CREATE TABLE @extschema@.action_permissions (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    resource_id      BIGINT      REFERENCES @extschema@.resources(id) ON DELETE CASCADE,
    principal_id     BIGINT      REFERENCES @extschema@.principals(id) ON DELETE CASCADE,
    action_id        BIGINT      REFERENCES @extschema@.actions(id) ON DELETE CASCADE,
    access           TEXT        NOT NULL CHECK (access IN ('ALLOW', 'DENY')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_id, principal_id, action_id)
    );
CREATE INDEX idx_action_permissions_resource ON @extschema@.action_permissions(resource_id);
CREATE INDEX idx_action_permissions_principal ON @extschema@.action_permissions(principal_id);
CREATE INDEX idx_action_permissions_action ON @extschema@.action_permissions(action_id);
CREATE INDEX idx_action_permissions_all ON @extschema@.action_permissions(principal_id, action_id, resource_id);
ALTER TABLE @extschema@.action_permissions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.action_permissions TO service_role;

CREATE TABLE @extschema@.role_permissions (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    resource_id      BIGINT      REFERENCES @extschema@.resources(id) ON DELETE CASCADE,
    role_id          BIGINT      REFERENCES @extschema@.roles(id) ON DELETE CASCADE,
    principal_id     BIGINT      REFERENCES @extschema@.principals(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_id, role_id, principal_id)
    );
CREATE INDEX idx_role_permissions_resource ON @extschema@.role_permissions(resource_id);
CREATE INDEX idx_role_permissions_role ON @extschema@.role_permissions(role_id);
CREATE INDEX idx_role_permissions_principal ON @extschema@.role_permissions(principal_id);
CREATE INDEX idx_role_permissions_all ON @extschema@.role_permissions(principal_id, role_id, resource_id);
ALTER TABLE @extschema@.role_permissions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.role_permissions TO service_role;

CREATE OR REPLACE FUNCTION @extschema@.principal(p_principal_type TEXT, p_principal_uuid UUID)
  RETURNS BIGINT
  SECURITY DEFINER
  LANGUAGE plpgsql
  AS $$
  BEGIN
      RETURN (SELECT id FROM @extschema@.principals WHERE principal_type = p_principal_type AND principal_uuid = p_principal_uuid LIMIT 1);
  END;
  $$;

CREATE OR REPLACE FUNCTION @extschema@.role(p_role_name TEXT)
  RETURNS BIGINT
  SECURITY DEFINER
  LANGUAGE plpgsql
  AS $$
  BEGIN
      RETURN (SELECT id FROM @extschema@.roles WHERE role_name = p_role_name LIMIT 1);
  END;
  $$;

CREATE OR REPLACE FUNCTION @extschema@.resource(p_resource_type TEXT, p_resource_uuid UUID)
  RETURNS BIGINT
  SECURITY DEFINER
  LANGUAGE plpgsql
  AS $$
  BEGIN
      RETURN (SELECT id FROM @extschema@.resources WHERE resource_type = p_resource_type AND resource_uuid = p_resource_uuid LIMIT 1);
  END;
  $$;

CREATE OR REPLACE FUNCTION @extschema@.action(p_action_name TEXT)
  RETURNS BIGINT
  SECURITY DEFINER
  LANGUAGE plpgsql
  AS $$
  BEGIN
      RETURN (SELECT id FROM @extschema@.actions WHERE action_name = p_action_name LIMIT 1);
  END;
  $$;

CREATE OR REPLACE FUNCTION @extschema@.has_action_permission(
    p_principal_id BIGINT,
    p_action_id    BIGINT,
    p_resource_id  BIGINT
  )
  RETURNS BOOLEAN
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER 
  SET search_path = @extschema@
  AS $$
  DECLARE
      v_principal_id BIGINT;
      v_resource_id  BIGINT;
      v_access       TEXT;
  BEGIN
      -- Walk up the principal hierarchy (outer loop)
      v_principal_id := p_principal_id;
      WHILE v_principal_id IS NOT NULL LOOP

          -- For this principal, walk up the resource hierarchy (inner loop)
          v_resource_id := p_resource_id;
          WHILE v_resource_id IS NOT NULL LOOP

              SELECT sp.access
              INTO   v_access
              FROM   @extschema@.action_permissions sp
              WHERE  sp.principal_id = v_principal_id
              AND    sp.action_id    = p_action_id
              AND    sp.resource_id  = v_resource_id
              LIMIT  1;

              -- First defined permission wins
              IF FOUND THEN
                  RETURN v_access = 'ALLOW';
              END IF;

              -- Step one level up the resource hierarchy
              SELECT r.parent_id
              INTO   v_resource_id
              FROM   @extschema@.resources r
              WHERE  r.id = v_resource_id;

          END LOOP;

          -- Resource hierarchy exhausted: step up the principal hierarchy
          SELECT p.parent_id
          INTO   v_principal_id
          FROM   @extschema@.principals p
          WHERE  p.id = v_principal_id;

      END LOOP;

      -- No permission found anywhere: default DENY
      RETURN FALSE;
  END;
  $$;


CREATE OR REPLACE FUNCTION @extschema@.has_role_permission(
    p_principal_id BIGINT,
    p_role_id    BIGINT,
    p_resource_id  BIGINT
  )
  RETURNS BOOLEAN
  LANGUAGE plpgsql
  STABLE
  SECURITY DEFINER 
  SET search_path = @extschema@
  AS $$
  DECLARE
      v_principal_id BIGINT;
      v_resource_id  BIGINT;
      v_access       TEXT;
  BEGIN
      -- Walk up the principal hierarchy (outer loop)
      v_principal_id := p_principal_id;
      WHILE v_principal_id IS NOT NULL LOOP

          -- For this principal, walk up the resource hierarchy (inner loop)
          v_resource_id := p_resource_id;
          WHILE v_resource_id IS NOT NULL LOOP
            
              SELECT 1
              INTO   v_access
              FROM   @extschema@.role_permissions rp
              WHERE  rp.principal_id = v_principal_id
              AND    rp.role_id    = p_role_id
              AND    rp.resource_id  = v_resource_id
              LIMIT  1;

              -- First defined permission wins
              IF FOUND THEN
                  RETURN TRUE;
              END IF;

              -- Step one level up the resource hierarchy
              SELECT r.parent_id
              INTO   v_resource_id
              FROM   @extschema@.resources r
              WHERE  r.id = v_resource_id;

          END LOOP;

          -- Resource hierarchy exhausted: step up the principal hierarchy
          SELECT p.parent_id
          INTO   v_principal_id
          FROM   @extschema@.principals p
          WHERE  p.id = v_principal_id;

      END LOOP;

      -- No permission found anywhere: default DENY
      RETURN FALSE;
  END;
  $$;

GRANT USAGE, CREATE ON SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA @extschema@ TO service_role;