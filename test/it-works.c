
#include "tabled-config.h"
#include <string.h>
#include <locale.h>
#include <s3c.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct s3_client *s3c;
	struct s3_blist *blist;

	setlocale(LC_ALL, "C");

	s3c = s3c_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(s3c);

	blist = s3c_list_buckets(s3c);
	OK(blist);

	OK(!strcmp(blist->own_id, s3c->user));
	OK(!strcmp(blist->own_name, s3c->user));
	OK(!blist->list);

	return 0;
}
