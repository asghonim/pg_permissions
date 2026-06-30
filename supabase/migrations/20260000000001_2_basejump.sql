CREATE EXTENSION IF NOT EXISTS pgtap;
SELECT * FROM pg_available_extensions WHERE name = 'pgtap';

select dbdev.install('basejump-supabase_test_helpers');
CREATE EXTENSION "basejump-supabase_test_helpers";