create table users (
  userid integer primary key,
  login varchar(50) unique not null,
  pass character(64),
  url varchar(300)
);

create table devices (
  hwaddr character(17) primary key,
  name varchar(50),
  owner integer references users(userid),
  ignored boolean
);
