BEGIN;

CREATE TABLE IF NOT EXISTS admins (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(32) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS admins_username_lower_unique
  ON admins (LOWER(username));
CREATE UNIQUE INDEX IF NOT EXISTS admins_email_lower_unique
  ON admins (LOWER(email));

CREATE TABLE IF NOT EXISTS discographies (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  image_url TEXT NOT NULL,
  type VARCHAR(10) NOT NULL CHECK (type IN ('album', 'single')),
  year SMALLINT NOT NULL CHECK (year BETWEEN 1900 AND 2100),
  spotify_url TEXT NOT NULL,
  soundcloud_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS selected_works (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  image_url TEXT,
  category VARCHAR(10) NOT NULL CHECK (category IN ('video', 'music', 'photo', 'album')),
  year SMALLINT NOT NULL CHECK (year BETWEEN 1900 AND 2100),
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS galleries (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  year SMALLINT NOT NULL CHECK (year BETWEEN 1900 AND 2100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS gallery_images (
  id BIGSERIAL PRIMARY KEY,
  gallery_id BIGINT NOT NULL REFERENCES galleries(id) ON DELETE CASCADE,
  image_url TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS discographies_created_idx ON discographies (created_at DESC);
CREATE INDEX IF NOT EXISTS selected_works_created_idx ON selected_works (created_at DESC);
CREATE INDEX IF NOT EXISTS galleries_created_idx ON galleries (created_at DESC);
CREATE INDEX IF NOT EXISTS gallery_images_gallery_idx ON gallery_images (gallery_id, position, id);

COMMIT;
