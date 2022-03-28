#ifndef ATBM_OS_ATOMIC_H
#define ATBM_OS_ATOMIC_H
//#include <drvBitops.h>
typedef struct {
	int counter;
} atomic_t;
#define atbm_clear_bit(a, b) //ms_clear_bit(a, b, U32)
#define atbm_set_bit(a, b) //ms_set_bit(a, b, U32)

#define atbm_atomic_read(a) osapi_atomic_read(a)
#define atbm_atomic_set(a,b) osapi_atomic_set(a,b)
int atbm_atomic_xchg(atomic_t *count,int value);
int atbm_atomic_add_return(int value,atomic_t *count);
#define atbm_atomic_sub_return(i, v)	(atbm_atomic_add_return(-(int)(i), (v)))
int atbm_local_irq_save();
atbm_void atbm_local_irq_restore(int Istate);


#endif /* ATBM_OS_ATOMIC_H */

