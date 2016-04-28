drop table if exists users;
create table users (
  id integer primary key autoincrement,
  ip text not null,
  username text not null,
  score integer DEFAULT 0
);

INSERT INTO users (ip, username) VALUES ("120.0.0.123", "Test Guy");
