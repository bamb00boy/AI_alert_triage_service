-- Core pipeline tables: alerts, idempotency, cases, append-only audit log.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Every accepted webhook payload. queued_at is set only after RabbitMQ confirms the
-- publish, so a crash between insert and publish is recovered by the client's retry.
CREATE TABLE alerts (
    alert_id     text PRIMARY KEY,
    source       text NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    queued_at    timestamptz,
    alert        jsonb NOT NULL,
    raw          jsonb
);

-- Worker-side idempotency. A row is "claimed" with a lease; the lease is renewed while
-- the worker is alive, so a crashed worker's message is picked up once it expires.
CREATE TABLE idempotency (
    key          text PRIMARY KEY,
    status       text NOT NULL CHECK (status IN ('processing', 'done', 'dead')),
    owner        text,
    attempts     integer NOT NULL DEFAULT 1,
    lease_until  timestamptz,
    last_error   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cases (
    case_id             bigserial PRIMARY KEY,
    alert_id            text NOT NULL UNIQUE REFERENCES alerts (alert_id),
    status              text NOT NULL
                        CHECK (status IN ('pending_approval', 'auto_closed', 'approved', 'rejected')),
    verdict             text,
    technique_id        text,
    tactics             text[] NOT NULL DEFAULT '{}',
    recommended_action  text,
    confidence          real,
    severity            text,
    rule_title          text,
    gate_reasons        text[] NOT NULL DEFAULT '{}',
    decision            jsonb,          -- validated model output
    enrichment          jsonb,
    candidates          jsonb,          -- retrieved ATT&CK techniques shown to the model
    llm_attempts        jsonb,          -- per-provider attempts incl. fallback reasons
    provider            text,
    model               text,
    prompt_version      text,
    trace_id            text,
    final_decision      jsonb,          -- what the analyst approved (possibly edited)
    decided_by          text,
    decided_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cases_status_created_idx ON cases (status, created_at DESC);

-- Append-only, hash-chained audit log -----------------------------------------------
CREATE TABLE audit_log (
    seq          bigserial PRIMARY KEY,
    ts           timestamptz NOT NULL,
    actor        text NOT NULL,
    event_type   text NOT NULL,
    entity_type  text NOT NULL,
    entity_id    text NOT NULL,
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    trace_id     text,
    prev_hash    bytea,
    hash         bytea NOT NULL
);
CREATE INDEX audit_log_entity_idx ON audit_log (entity_type, entity_id, seq);

-- Canonical byte string that each row's hash covers. jsonb::text is deterministic, and
-- the timestamp is rendered as epoch microseconds so the session TimeZone can't change it.
CREATE FUNCTION audit_canonical(
    p_prev bytea, p_ts timestamptz, p_actor text, p_event text, p_entity_type text,
    p_entity_id text, p_payload jsonb, p_trace text
) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(p_prev, '\x'::bytea) || convert_to(
        concat_ws(E'\x1f',
            (extract(epoch FROM p_ts) * 1000000)::bigint::text,
            p_actor, p_event, p_entity_type, p_entity_id, p_payload::text, coalesce(p_trace, '')),
        'UTF8')
$$;

-- The only write path into audit_log. SECURITY DEFINER so the application role can append
-- without holding INSERT on the table; the advisory lock serialises the hash chain.
CREATE FUNCTION audit_append(
    p_actor text, p_event text, p_entity_type text, p_entity_id text,
    p_payload jsonb DEFAULT '{}'::jsonb, p_trace text DEFAULT NULL
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_prev bytea;
    v_ts   timestamptz := clock_timestamp();
    v_seq  bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit_log'));
    SELECT hash INTO v_prev FROM audit_log ORDER BY seq DESC LIMIT 1;
    INSERT INTO audit_log (ts, actor, event_type, entity_type, entity_id, payload, trace_id, prev_hash, hash)
    VALUES (v_ts, p_actor, p_event, p_entity_type, p_entity_id, p_payload, p_trace, v_prev,
            sha256(audit_canonical(v_prev, v_ts, p_actor, p_event, p_entity_type, p_entity_id, p_payload, p_trace)))
    RETURNING seq INTO v_seq;
    RETURN v_seq;
END $$;

CREATE FUNCTION audit_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP;
END $$;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_forbid_mutation();
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_forbid_mutation();

-- Recomputes every hash and link; returns only the rows that fail.
CREATE FUNCTION audit_verify() RETURNS TABLE (seq bigint, problem text) LANGUAGE sql STABLE AS $$
    WITH chk AS (
        SELECT a.seq,
               a.hash = sha256(audit_canonical(a.prev_hash, a.ts, a.actor, a.event_type, a.entity_type,
                                               a.entity_id, a.payload, a.trace_id)) AS hash_ok,
               a.prev_hash IS NOT DISTINCT FROM lag(a.hash) OVER (ORDER BY a.seq) AS link_ok
        FROM audit_log a
    )
    SELECT seq, CASE WHEN NOT hash_ok THEN 'hash mismatch' ELSE 'broken link' END
    FROM chk WHERE NOT (hash_ok AND link_ok)
$$;
