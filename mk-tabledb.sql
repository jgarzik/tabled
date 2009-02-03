create table buckets (
	name		text primary key,
	owner		text not null,
	time_create	integer not null
);

create index bucket_idx on buckets (owner);

create table objects (
	bucket		text not null,
	key		text not null,
	md5		text not null,
	name		text not null,
	owner		text not null
);

create unique index obj_idx on objects (bucket, key);

create table acls (
	bucket		text not null,
	key		text,
	grantee		text not null,
	perm		text not null
);

create index acl_idx on acls (bucket, key);

create table headers (
	bucket		text not null,
	key		text not null,
	header		text not null,
	header_val	text not null
);

create index header_idx on headers (bucket, key);
