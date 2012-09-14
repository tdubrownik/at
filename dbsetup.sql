create table devices (
  hwaddr character(17) primary key,
  name varchar(50),
  owner varchar(100) not null, 
  ignored boolean
);
