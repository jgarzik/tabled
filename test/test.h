#ifndef __TABLED_TEST_H__
#define __TABLED_TEST_H__

#include <stdlib.h>
#include <stdio.h>

#define TEST_HOST "pretzel.yyz.us"
#define TEST_USER "testuser"
#define TEST_USER_KEY "testpw"

#define OK(expr)				\
	do {					\
		if (!(expr)) {			\
			fprintf(stderr, "test failed on line %d\n", \
				__LINE__);	\
			exit(1);		\
		}				\
	} while (0)

#endif /* __TABLED_TEST_H__ */
