-- Local threat-intel store served by ti-service.

CREATE TABLE ti_networks (
    network   cidr NOT NULL,
    source    text NOT NULL,
    category  text,
    PRIMARY KEY (network, source)
);
-- GiST over inet_ops makes "which listed networks contain this IP" (>>=) an index scan.
CREATE INDEX ti_networks_gist ON ti_networks USING gist (network inet_ops);

CREATE TABLE ti_domains (
    domain    text NOT NULL,
    verdict   text NOT NULL CHECK (verdict IN ('malicious', 'benign')),
    source    text NOT NULL,
    category  text,
    rank      integer,
    PRIMARY KEY (domain, source)
);

CREATE TABLE ti_meta (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
