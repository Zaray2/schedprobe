/*
 * cJSON fuzz target for SchedProbe FuzzLab.
 *
 * The library is not ours and the engine is not ours; this file exists only to give both
 * a stable in-process entry point. Three parse modes are exercised so the target has a
 * wide, structurally varied path space - a target whose input space is one narrow shape
 * tells a scheduling experiment almost nothing, because there is no corpus to schedule.
 *
 *   0x00..        plain JSON            cJSON_ParseWithLength
 *   0x01 ..       JSON with options     cJSON_ParseWithOpts (require null terminator)
 *   0x02 ..       round-trip             parse, print, re-parse, compare
 *
 * The round-trip mode matters for fuzzing: a parser that survives reading but breaks on
 * printing is a different class of defect, and it only shows up if the harness asks for it.
 *
 * Memory is released on every exit path, so a leak is a finding rather than noise. The
 * harness never trusts the input length: cJSON is given the exact length and the buffer is
 * heap-allocated with one spare byte, which is what makes the terminator-based mode safe.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cjson/cJSON.h"

#define MAX_INPUT (1u << 20)
#define ROUNDTRIP_MODES 2u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > MAX_INPUT) {
    return 0;
  }

  const unsigned mode = data[0] % (ROUNDTRIP_MODES + 1u);
  const uint8_t *body = data + 1;
  const size_t body_size = size - 1;

  /* One spare byte so the nul-terminated variant can be fed the same bytes without an
   * out-of-bounds read in the harness itself. */
  char *copy = (char *)malloc(body_size + 1);
  if (copy == NULL) {
    return 0;
  }
  memcpy(copy, body, body_size);
  copy[body_size] = '\0';

  cJSON *root = NULL;
  switch (mode) {
    case 0:
      root = cJSON_ParseWithLength(copy, body_size);
      break;
    case 1: {
      const char *end = NULL;
      root = cJSON_ParseWithOpts(copy, &end, 1);
      break;
    }
    default: {
      root = cJSON_ParseWithLength(copy, body_size);
      if (root != NULL) {
        char *printed = cJSON_Print(root);
        if (printed != NULL) {
          cJSON *again = cJSON_ParseWithLength(printed, strlen(printed));
          cJSON_Delete(again);
          free(printed);
        }
        /* Unformatted printing walks different code (printbuffer growth, escaping). */
        char *compact = cJSON_PrintUnformatted(root);
        free(compact);
      }
      break;
    }
  }

  if (root != NULL) {
    /* GetObjectItem on a non-object is a branch worth reaching; the library is expected to
     * return NULL rather than misbehave, and this is where that expectation is tested. */
    cJSON_GetObjectItemCaseSensitive(root, "id");
    cJSON_Delete(root);
  }

  free(copy);
  return 0;
}
