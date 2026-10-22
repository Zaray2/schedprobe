/*
 * Minimal AFL++ type definitions for the FuzzLab hook.
 *
 * Why not `#include "afl-fuzz.h"`: that header describes AFL++'s internal state struct, and
 * depending on it couples this plugin to one AFL++ version's private layout. The plugin only
 * needs the fixed-width typedefs and a forward declaration of `afl_state_t` (it never
 * dereferences the state), so it declares those itself. The result compiles against any
 * AFL++ 4.x without the headers installed, which also makes the build reproducible on a
 * machine that only has the binaries.
 */

#ifndef FUZZLAB_AFL_TYPES_H
#define FUZZLAB_AFL_TYPES_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* Opaque: the hook receives a pointer but never reads through it. */
typedef struct afl_state afl_state_t;

#endif /* FUZZLAB_AFL_TYPES_H */
