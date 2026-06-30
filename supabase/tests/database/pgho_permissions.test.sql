begin;
select plan(2);

-- Create a test user (triggers on_auth_user_inserted, which creates a principal)
select tests.create_supabase_user('user1');

-- Create a tenant as superuser/service_role (triggers create_tenant_resource_trigger,
-- which creates a resource entry in pgho_permissions.resources)
insert into public.tenants (slug) values ('test-tenant');

-- As user1, they should NOT see the tenant — no role_permissions row exists yet
select tests.authenticate_as('user1');

select is(
    (select count(*)::int from public.tenants),
    0,
    'user without tenant_admin role cannot see the tenant'
);

-- Back to superuser to grant the role
select tests.clear_authentication();
set local role postgres;

insert into pgho_permissions.role_permissions (role_id, principal_id, resource_id)
values (
    pgho_permissions.role('tenant_admin'),
    pgho_permissions.principal('user', tests.get_supabase_uid('user1')),
    pgho_permissions.resource('tenant', (select uid from public.tenants where slug = 'test-tenant'))
);

-- As user1 again, they should NOW see the tenant
select tests.authenticate_as('user1');

select is(
    (select count(*)::int from public.tenants),
    1,
    'user with tenant_admin role can see the tenant'
);

select * from finish();
rollback;
