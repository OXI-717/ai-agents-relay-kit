-- Этап 2: статистика трафика, heartbeat серверов, состояние подписок, дебаунс алертов.
CREATE TABLE ingest_batches (
  server      TEXT NOT NULL,
  batch_id    TEXT NOT NULL,
  received_at INTEGER NOT NULL, -- unix seconds
  PRIMARY KEY (server, batch_id)
);
CREATE TABLE traffic_hourly (
  server   TEXT NOT NULL,
  user_ref TEXT NOT NULL,
  hour_utc INTEGER NOT NULL, -- unix seconds, начало часа
  up       INTEGER NOT NULL DEFAULT 0,
  down     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server, user_ref, hour_utc)
);
-- Служебный трафик relay→exit: нагрузка сервера, не суммируется с пользовательским.
CREATE TABLE service_traffic_hourly (
  server   TEXT NOT NULL,
  svc      TEXT NOT NULL, -- svc:<relay>><exit>
  hour_utc INTEGER NOT NULL,
  up       INTEGER NOT NULL DEFAULT 0,
  down     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server, svc, hour_utc)
);
CREATE TABLE server_state (
  server   TEXT PRIMARY KEY,
  seen_at  INTEGER NOT NULL,
  payload  TEXT NOT NULL -- JSON heartbeat последнего пакета
);
CREATE TABLE server_history (
  server   TEXT NOT NULL,
  seen_at  INTEGER NOT NULL,
  payload  TEXT NOT NULL,
  PRIMARY KEY (server, seen_at)
);
CREATE TABLE sub_state (
  user_ref        TEXT PRIMARY KEY,
  last_fetch_hour INTEGER NOT NULL, -- округлено до часа
  client_family   TEXT NOT NULL,
  format          TEXT NOT NULL
);
CREATE TABLE alerts (
  kind    TEXT NOT NULL, -- 'silent'
  object  TEXT NOT NULL, -- server id
  sent_at INTEGER NOT NULL,
  PRIMARY KEY (kind, object)
);
