-- Re-applied after every migration run. The services connect as triage_app, which can
-- read and write pipeline tables but can only *append* to the audit log, via audit_append().

GRANT USAGE ON SCHEMA public TO triage_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO triage_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO triage_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO triage_app;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_log FROM triage_app;
REVOKE UPDATE, DELETE, TRUNCATE ON schema_migrations FROM triage_app;
REVOKE INSERT ON schema_migrations FROM triage_app;
