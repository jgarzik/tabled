
create table objects (
	bucket		text not null,
	key		text not null,
	md5		text not null,
	name		text not null,
	owner		text not null
);

create unique index obj_idx on objects (bucket, key);

create table headers (
	bucket		text not null,
	key		text not null,
	header		text not null,
	header_val	text not null
);

create index header_idx on headers (bucket, key);

