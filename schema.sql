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

-- FITUR BARU: MUSICS (Player Buble)
CREATE TABLE IF NOT EXISTS musics (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  thumbnail_url TEXT,
  mp3_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- FITUR BARU: ABOUT SECTION
CREATE TABLE IF NOT EXISTS about_section (
  id INT PRIMARY KEY DEFAULT 1,
  content TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexing lama
CREATE INDEX IF NOT EXISTS discographies_created_idx ON discographies (created_at DESC);
CREATE INDEX IF NOT EXISTS selected_works_created_idx ON selected_works (created_at DESC);
CREATE INDEX IF NOT EXISTS galleries_created_idx ON galleries (created_at DESC);
CREATE INDEX IF NOT EXISTS gallery_images_gallery_idx ON gallery_images (gallery_id, position, id);
CREATE INDEX IF NOT EXISTS musics_created_idx ON musics (created_at DESC);

-- Default isi About Section agar tidak kosong saat awal instalasi
INSERT INTO about_section (id, content) 
VALUES (1, '<p>I''m a self-taught editor and producer from Indonesia, chasing the same feeling in every project: something quiet turning into something alive.</p><p>Porter Robinson''s <em>nurture</em> is the record that shaped how I think about craft   soft colors holding sharp precision, restraint that still feels warm. That balance is what I try to bring into every cut, every mix, every frame.</p>') 
ON CONFLICT (id) DO NOTHING;

COMMIT;