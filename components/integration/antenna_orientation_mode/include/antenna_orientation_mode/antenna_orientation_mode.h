#ifndef _ANTENNA_ORIENTATION_MODE_H_
#define _ANTENNA_ORIENTATION_MODE_H_

#include <stdbool.h>
#include "ring_share/ring_share.h"

#ifdef __cplusplus
extern "C" {
#endif

bool antenna_orientation_mode_pin_is_active(void);
void antenna_orientation_mode_run(ring_share_t *rs);

#ifdef __cplusplus
}
#endif

#endif
