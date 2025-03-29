#include "fixed_point.h"

Q14 i_to_q14(int32_t n)
{
    return n * Q14_ONE;
}

int32_t q14_to_i_zero(Q14 x)
{
    return x / Q14_ONE;
}

int32_t q14_to_i_nearest(Q14 x)
{
    if (x >= 0) {
        return (x + Q14_ONE / 2) / Q14_ONE;
    }
    if (x <= 0) {
        return (x - Q14_ONE / 2) / Q14_ONE;
    }
}

Q14 q14_add_q14(Q14 x, Q14 y)
{
    return x + y;
}

Q14 q14_sub_q14(Q14 x, Q14 y)
{
    return x - y;
}

Q14 q14_add_i(Q14 x, int32_t n)
{
    return x + n * Q14_ONE;
}

Q14 q14_sub_i(Q14 x, int32_t n)
{
    return x - n * Q14_ONE;
}

Q14 q14_mul_q14(Q14 x, Q14 y)
{
    return ((int64_t) x) * y / Q14_ONE;
}

Q14 q14_mul_i(Q14 x, int32_t n)
{
    return x * n;
}

Q14 q14_div_q14(Q14 x, Q14 y)
{
    return ((int64_t) x) * Q14_ONE / y;
}

Q14 q14_div_i(Q14 x, int32_t n)
{
    return x / n;
}