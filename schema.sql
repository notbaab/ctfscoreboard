drop table if exists users;
create table users (
  id integer primary key autoincrement,
  ip text not null,
  username text not null,
  motto text not null,
  score integer DEFAULT 0
);
