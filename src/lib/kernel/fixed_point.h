#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

typedef int32_t Q14;

#define Q14_ONE ((int32_t)1 << 14)

Q14 i_to_q14(int32_t n);

int32_t q14_to_i_zero(Q14 x);

int32_t q14_to_i_nearest(Q14 x);

Q14 q14_add_q14(Q14 x, Q14 y);

Q14 q14_sub_q14(Q14 x, Q14 y);

Q14 q14_add_i(Q14 x, int32_t n);

Q14 q14_sub_i(Q14 x, int32_t n);

Q14 q14_mul_q14(Q14 x, Q14 y);

Q14 q14_mul_i(Q14 x, int32_t n);

Q14 q14_div_q14(Q14 x, Q14 y);

Q14 q14_div_i(Q14 x, int32_t n);

#endif