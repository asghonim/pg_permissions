CREATE SCHEMA IF NOT EXISTS private;
-- Trigger to create a principal when a new user is created
CREATE OR REPLACE FUNCTION private.on_auth_user_inserted()
  RETURNS TRIGGER 
  LANGUAGE plpgsql
  SECURITY DEFINER
  AS $$
  BEGIN
      -- Insert a new principal for the user into the principals table
      INSERT INTO pgho_permissions.principals (principal_type, principal_uuid)
      VALUES ('user', NEW.id);
      RETURN NEW;
  END;
  $$;
  CREATE TRIGGER on_auth_user_inserted AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION private.on_auth_user_inserted();

CREATE POLICY "SELECT principals"
  ON pgho_permissions.principals
  FOR SELECT
  USING (auth.uid() = principal_uuid AND principal_type = 'user');

CREATE OR REPLACE FUNCTION public.my_principal()
  RETURNS pgho_permissions.principals AS $$
  BEGIN
      RETURN (SELECT * FROM pgho_permissions.principals WHERE principal_type = 'user' AND principal_uuid = auth.uid());
  END;
  $$ LANGUAGE plpgsql;

CREATE TABLE public.tenants (
    id                           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid                          UUID        NOT NULL UNIQUE DEFAULT pgho_permissions.gen_uuid_v7(),
    slug                         TEXT        NOT NULL UNIQUE CHECK (char_length(slug) BETWEEN 1 AND 100),
    metadata                     JSONB       NOT NULL DEFAULT '{}',
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
  GRANT ALL ON TABLE public.tenants TO service_role;

INSERT INTO pgho_permissions.roles (role_name) VALUES ('tenant_admin');

CREATE OR REPLACE FUNCTION private.create_tenant_resource()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  SECURITY DEFINER 
  AS $$
  BEGIN
      -- Insert a new resource for the tenant into the resources table
      INSERT INTO pgho_permissions.resources (resource_type, resource_uuid)
      VALUES ('tenant', NEW.uid);
      RETURN NEW;
  END;
  $$;
  CREATE TRIGGER create_tenant_resource_trigger AFTER INSERT ON public.tenants FOR EACH ROW EXECUTE FUNCTION private.create_tenant_resource();

CREATE POLICY "SELECT tenants"
  ON public.tenants
  FOR SELECT
  USING (pgho_permissions.has_role_permission(
    (pgho_permissions.principal('user', auth.uid())),
    (pgho_permissions.role('tenant_admin')),
    (pgho_permissions.resource('tenant', public.tenants.uid))
  ));
  GRANT SELECT ON public.tenants TO authenticated;