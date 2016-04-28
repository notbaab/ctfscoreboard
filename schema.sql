drop table if exists users;
create table users (
  id integer primary key autoincrement,
  ip text not null,
  mac text not null,
  score integer
);
