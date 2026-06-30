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
    resource_uuid    UUID        NOT NULL,
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
    principal_uuid   UUID        NOT NULL,
    parent_id        BIGINT      REFERENCES @extschema@.principals(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (principal_type, principal_uuid)
    );
CREATE INDEX idx_principals_type_uuid ON @extschema@.principals(principal_type, principal_uuid);
CREATE INDEX idx_principals_parent ON @extschema@.principals(parent_id) WHERE parent_id IS NOT NULL;
ALTER TABLE @extschema@.principals ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.principals TO service_role;

-- ---------------------------------------------------------------------------
-- Closure tables
-- Materialise every ancestor/descendant pair with its hop distance.
-- Maintained automatically by triggers; never written by application code.
-- ---------------------------------------------------------------------------
CREATE TABLE @extschema@.resource_closure (
    ancestor_id   BIGINT NOT NULL REFERENCES @extschema@.resources(id)  ON DELETE CASCADE,
    descendant_id BIGINT NOT NULL REFERENCES @extschema@.resources(id)  ON DELETE CASCADE,
    depth         INT    NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
    );
-- Covering index for the "give me all ancestors of X" lookup in permission queries
CREATE INDEX idx_resource_closure_descendant ON @extschema@.resource_closure(descendant_id);
ALTER TABLE @extschema@.resource_closure ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.resource_closure TO service_role;

CREATE TABLE @extschema@.principal_closure (
    ancestor_id   BIGINT NOT NULL REFERENCES @extschema@.principals(id) ON DELETE CASCADE,
    descendant_id BIGINT NOT NULL REFERENCES @extschema@.principals(id) ON DELETE CASCADE,
    depth         INT    NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
    );
CREATE INDEX idx_principal_closure_descendant ON @extschema@.principal_closure(descendant_id);
ALTER TABLE @extschema@.principal_closure ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.principal_closure TO service_role;

-- ---------------------------------------------------------------------------
-- Resource closure triggers
-- ---------------------------------------------------------------------------

-- INSERT: add self-row and connect to existing ancestors through the parent.
CREATE OR REPLACE FUNCTION @extschema@.on_insert_resource()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    INSERT INTO @extschema@.resource_closure (ancestor_id, descendant_id, depth)
    VALUES (NEW.id, NEW.id, 0);

    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO @extschema@.resource_closure (ancestor_id, descendant_id, depth)
        SELECT ancestor_id, NEW.id, depth + 1
        FROM   @extschema@.resource_closure
        WHERE  descendant_id = NEW.parent_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_insert_resource
    AFTER INSERT ON @extschema@.resources
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_insert_resource();

-- UPDATE OF parent_id: cycle-check, then re-graft the subtree.
CREATE OR REPLACE FUNCTION @extschema@.on_reparent_resource()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    IF OLD.parent_id IS NOT DISTINCT FROM NEW.parent_id THEN
        RETURN NEW;
    END IF;

    IF NEW.parent_id IS NOT NULL THEN
        IF NEW.parent_id = NEW.id THEN
            RAISE EXCEPTION 'resource % cannot be its own parent', NEW.id;
        END IF;

        -- New parent must not already be a descendant of this node
        IF EXISTS (
            SELECT 1
            FROM   @extschema@.resource_closure
            WHERE  ancestor_id   = NEW.id
              AND  descendant_id = NEW.parent_id
              AND  depth > 0
        ) THEN
            RAISE EXCEPTION
                'setting parent_id = % on resource % would create a cycle in the resource hierarchy',
                NEW.parent_id, NEW.id;
        END IF;
    END IF;

    -- Remove all ancestry edges that enter the subtree from outside it
    DELETE FROM @extschema@.resource_closure
    WHERE  descendant_id IN (
               SELECT descendant_id
               FROM   @extschema@.resource_closure
               WHERE  ancestor_id = NEW.id          -- subtree including self
           )
      AND  ancestor_id NOT IN (
               SELECT descendant_id
               FROM   @extschema@.resource_closure
               WHERE  ancestor_id = NEW.id          -- same subtree
           );

    -- Graft new ancestry edges from the new parent's ancestors to every
    -- node in the subtree.  +1 accounts for the new parent→node edge.
    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO @extschema@.resource_closure (ancestor_id, descendant_id, depth)
        SELECT p.ancestor_id, c.descendant_id, p.depth + 1 + c.depth
        FROM   @extschema@.resource_closure p
        JOIN   @extschema@.resource_closure c ON c.ancestor_id = NEW.id
        WHERE  p.descendant_id = NEW.parent_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_reparent_resource
    AFTER UPDATE OF parent_id ON @extschema@.resources
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_reparent_resource();

-- DELETE: detach the subtree before ON DELETE CASCADE removes the node's own rows.
-- Children will become roots (ON DELETE SET NULL on resources.parent_id).
-- Their ancestry rows that passed through the deleted node must be removed here
-- because CASCADE only cleans up rows that directly name OLD.id.
CREATE OR REPLACE FUNCTION @extschema@.on_delete_resource()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    DELETE FROM @extschema@.resource_closure
    WHERE  descendant_id IN (
               SELECT descendant_id
               FROM   @extschema@.resource_closure
               WHERE  ancestor_id = OLD.id AND depth > 0
           )
      AND  ancestor_id IN (
               SELECT ancestor_id
               FROM   @extschema@.resource_closure
               WHERE  descendant_id = OLD.id
           );

    RETURN OLD;
END;
$$;

CREATE TRIGGER on_delete_resource
    BEFORE DELETE ON @extschema@.resources
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_delete_resource();

-- ---------------------------------------------------------------------------
-- Principal closure triggers  (mirror of resource triggers)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION @extschema@.on_insert_principal()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    INSERT INTO @extschema@.principal_closure (ancestor_id, descendant_id, depth)
    VALUES (NEW.id, NEW.id, 0);

    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO @extschema@.principal_closure (ancestor_id, descendant_id, depth)
        SELECT ancestor_id, NEW.id, depth + 1
        FROM   @extschema@.principal_closure
        WHERE  descendant_id = NEW.parent_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_insert_principal
    AFTER INSERT ON @extschema@.principals
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_insert_principal();

CREATE OR REPLACE FUNCTION @extschema@.on_reparent_principal()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    IF OLD.parent_id IS NOT DISTINCT FROM NEW.parent_id THEN
        RETURN NEW;
    END IF;

    IF NEW.parent_id IS NOT NULL THEN
        IF NEW.parent_id = NEW.id THEN
            RAISE EXCEPTION 'principal % cannot be its own parent', NEW.id;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM   @extschema@.principal_closure
            WHERE  ancestor_id   = NEW.id
              AND  descendant_id = NEW.parent_id
              AND  depth > 0
        ) THEN
            RAISE EXCEPTION
                'setting parent_id = % on principal % would create a cycle in the principal hierarchy',
                NEW.parent_id, NEW.id;
        END IF;
    END IF;

    DELETE FROM @extschema@.principal_closure
    WHERE  descendant_id IN (
               SELECT descendant_id
               FROM   @extschema@.principal_closure
               WHERE  ancestor_id = NEW.id
           )
      AND  ancestor_id NOT IN (
               SELECT descendant_id
               FROM   @extschema@.principal_closure
               WHERE  ancestor_id = NEW.id
           );

    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO @extschema@.principal_closure (ancestor_id, descendant_id, depth)
        SELECT p.ancestor_id, c.descendant_id, p.depth + 1 + c.depth
        FROM   @extschema@.principal_closure p
        JOIN   @extschema@.principal_closure c ON c.ancestor_id = NEW.id
        WHERE  p.descendant_id = NEW.parent_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_reparent_principal
    AFTER UPDATE OF parent_id ON @extschema@.principals
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_reparent_principal();

CREATE OR REPLACE FUNCTION @extschema@.on_delete_principal()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    DELETE FROM @extschema@.principal_closure
    WHERE  descendant_id IN (
               SELECT descendant_id
               FROM   @extschema@.principal_closure
               WHERE  ancestor_id = OLD.id AND depth > 0
           )
      AND  ancestor_id IN (
               SELECT ancestor_id
               FROM   @extschema@.principal_closure
               WHERE  descendant_id = OLD.id
           );

    RETURN OLD;
END;
$$;

CREATE TRIGGER on_delete_principal
    BEFORE DELETE ON @extschema@.principals
    FOR EACH ROW EXECUTE FUNCTION @extschema@.on_delete_principal();

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
    resource_id      BIGINT      REFERENCES @extschema@.resources(id)   ON DELETE CASCADE,
    principal_id     BIGINT      REFERENCES @extschema@.principals(id)  ON DELETE CASCADE,
    action_id        BIGINT      REFERENCES @extschema@.actions(id)     ON DELETE CASCADE,
    access           TEXT        NOT NULL CHECK (access IN ('ALLOW', 'DENY')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_id, principal_id, action_id)
    );
CREATE INDEX idx_action_permissions_resource  ON @extschema@.action_permissions(resource_id);
CREATE INDEX idx_action_permissions_principal ON @extschema@.action_permissions(principal_id);
CREATE INDEX idx_action_permissions_action    ON @extschema@.action_permissions(action_id);
CREATE INDEX idx_action_permissions_all       ON @extschema@.action_permissions(principal_id, action_id, resource_id);
ALTER TABLE @extschema@.action_permissions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.action_permissions TO service_role;

CREATE TABLE @extschema@.role_permissions (
    id               BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid              UUID        NOT NULL UNIQUE DEFAULT @extschema@.gen_uuid_v7(),
    resource_id      BIGINT      REFERENCES @extschema@.resources(id)   ON DELETE CASCADE,
    role_id          BIGINT      REFERENCES @extschema@.roles(id)       ON DELETE CASCADE,
    principal_id     BIGINT      REFERENCES @extschema@.principals(id)  ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_id, role_id, principal_id)
    );
CREATE INDEX idx_role_permissions_resource  ON @extschema@.role_permissions(resource_id);
CREATE INDEX idx_role_permissions_role      ON @extschema@.role_permissions(role_id);
CREATE INDEX idx_role_permissions_principal ON @extschema@.role_permissions(principal_id);
CREATE INDEX idx_role_permissions_all       ON @extschema@.role_permissions(principal_id, role_id, resource_id);
ALTER TABLE @extschema@.role_permissions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE @extschema@.role_permissions TO service_role;

CREATE OR REPLACE FUNCTION @extschema@.principal(p_principal_type TEXT, p_principal_uuid UUID)
  RETURNS BIGINT
  SECURITY DEFINER
  LANGUAGE plpgsql
  AS $$
  BEGIN
      IF p_principal_uuid IS NULL THEN
          RAISE EXCEPTION 'principal_uuid must not be NULL';
      END IF;
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
      IF p_resource_uuid IS NULL THEN
          RAISE EXCEPTION 'resource_uuid must not be NULL';
      END IF;
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
  REVOKE EXECUTE ON FUNCTION @extschema@.action(TEXT) FROM public;


-- ---------------------------------------------------------------------------
-- Permission checks
-- Both functions resolve the full ancestor set for the given principal and
-- resource via the closure tables (single join, no loops), then pick the
-- most-specific matching rule ordered by principal proximity first, resource
-- proximity second — preserving the same precedence as the former loop-based
-- implementation.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION @extschema@.has_action_permission(
    p_principal_id BIGINT,
    p_action_id    BIGINT,
    p_resource_id  BIGINT
  )
  RETURNS BOOLEAN
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = @extschema@
  AS $$
    SELECT COALESCE(
        (SELECT ap.access = 'ALLOW'
         FROM   action_permissions  ap
         JOIN   principal_closure   pc ON pc.ancestor_id = ap.principal_id
         JOIN   resource_closure    rc ON rc.ancestor_id = ap.resource_id
         WHERE  pc.descendant_id = p_principal_id
           AND  rc.descendant_id = p_resource_id
           AND  ap.action_id     = p_action_id
         ORDER BY pc.depth ASC, rc.depth ASC
         LIMIT 1),
        FALSE
    );
  $$;


CREATE OR REPLACE FUNCTION @extschema@.has_role_permission(
    p_principal_id BIGINT,
    p_role_id      BIGINT,
    p_resource_id  BIGINT
  )
  RETURNS BOOLEAN
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = @extschema@
  AS $$
    SELECT EXISTS (
        SELECT 1
        FROM   role_permissions   rp
        JOIN   principal_closure  pc ON pc.ancestor_id = rp.principal_id
        JOIN   resource_closure   rc ON rc.ancestor_id = rp.resource_id
        WHERE  pc.descendant_id = p_principal_id
          AND  rc.descendant_id = p_resource_id
          AND  rp.role_id       = p_role_id
    );
  $$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA @extschema@ FROM public;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA @extschema@ FROM public;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA @extschema@ FROM public;
REVOKE ALL PRIVILEGES ON SCHEMA @extschema@ FROM public;

-- Allow application roles to call the SECURITY DEFINER API from RLS policies
GRANT USAGE ON SCHEMA @extschema@ TO public;
GRANT EXECUTE ON FUNCTION @extschema@.principal(TEXT, UUID) TO public;
GRANT EXECUTE ON FUNCTION @extschema@.resource(TEXT, UUID) TO public;
GRANT EXECUTE ON FUNCTION @extschema@.role(TEXT) TO public;
GRANT EXECUTE ON FUNCTION @extschema@.action(TEXT) TO public;
GRANT EXECUTE ON FUNCTION @extschema@.has_role_permission(BIGINT, BIGINT, BIGINT) TO public;
GRANT EXECUTE ON FUNCTION @extschema@.has_action_permission(BIGINT, BIGINT, BIGINT) TO public;

GRANT USAGE, CREATE ON SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA @extschema@ TO service_role;
GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA @extschema@ TO service_role;
