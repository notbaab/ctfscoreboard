drop table if exists users;
create table users (
  id integer primary key autoincrement,
  ip text NOT NULL UNIQUE,
  username text not null,
  score integer DEFAULT 0
);

drop table if exists vulnerable_services;
create table vulnerable_services (
  user_id integer NOT NULL,
  service text NOT NULL,
  uptime integer DEFAULT 0,
  downtime integer DEFAULT 0,
  vulnerable boolean DEFAULT true,
  available boolean DEFAULT true,
  PRIMARY KEY (user_id, service),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
