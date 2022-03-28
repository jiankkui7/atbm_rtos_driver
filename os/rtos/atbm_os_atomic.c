#include "atbm_os_atomic.h"
int atbm_atomic_xchg(atomic_t *count,int value)
{
	int readAtomic=0;
	readAtomic=count->counter;
	(count->counter) = value;
	return readAtomic;
}
int atbm_atomic_add_return(int value,atomic_t *count)
{
	int addAtomic=0;
	addAtomic=((count->counter)+value);
	return addAtomic;
}


