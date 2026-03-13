CREATE TABLE IF NOT EXISTS licences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial TEXT NOT NULL UNIQUE,
  licence_key_hash TEXT NOT NULL UNIQUE,
  buyer_name TEXT,
  buyer_email TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'lifetime',
  order_ref TEXT,
  device_limit INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_validated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_licences_buyer_email ON licences(buyer_email);
CREATE INDEX IF NOT EXISTS idx_licences_status ON licences(status);

CREATE TABLE IF NOT EXISTS activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  licence_id INTEGER NOT NULL,
  install_id TEXT NOT NULL,
  device_name TEXT,
  app_version TEXT,
  activated_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  FOREIGN KEY (licence_id) REFERENCES licences(id) ON DELETE CASCADE,
  UNIQUE (licence_id, install_id)
);

CREATE INDEX IF NOT EXISTS idx_activations_licence_id ON activations(licence_id);
