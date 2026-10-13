-- One row (chunk) per ATT&CK technique, embedded with bge-small-en-v1.5 (384 dims).

CREATE TABLE attack_techniques (
    technique_id     text PRIMARY KEY,
    name             text NOT NULL,
    tactics          text[] NOT NULL,
    is_subtechnique  boolean NOT NULL,
    summary          text NOT NULL,
    chunk            text NOT NULL,
    embedding        vector(384) NOT NULL,
    attack_version   text NOT NULL,
    embed_model      text NOT NULL
);

CREATE INDEX attack_techniques_hnsw ON attack_techniques USING hnsw (embedding vector_cosine_ops);
