
#include "tabled-config.h"
#include <string.h>
#include <locale.h>
#include <s3c.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct s3_client *s3c;
	struct s3_blist *blist;
	struct s3_bucket *buck;
	bool rcb;

	setlocale(LC_ALL, "C");

	s3c = s3c_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(s3c);

	/* make sure bucket list is empty */
	blist = s3c_list_buckets(s3c);
	OK(blist);
	OK(!blist->list);

	s3c_free_blist(blist);

	/* add bucket */
	rcb = s3c_add_bucket(s3c, "test1");
	OK(rcb);

	/* make sure bucket list contains one item */
	blist = s3c_list_buckets(s3c);
	OK(blist);
	OK(blist->list);
	OK(blist->list->next == NULL);

	buck = blist->list->data;
	OK(!strcmp(buck->name, "test1"));

	s3c_free_blist(blist);

	/* delete bucket */
	rcb = s3c_del_bucket(s3c, "test1");
	OK(rcb);

	/* make sure bucket list is empty */
	blist = s3c_list_buckets(s3c);
	OK(blist);
	OK(!blist->list);

	s3c_free_blist(blist);

	return 0;
}
