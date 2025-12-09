/*
 * Copyright 2024 Sony Semiconductor Solutions Corporation.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Sony Semiconductor
 * Solutions Corporation.
 * No part of this file may be copied, modified, sold, and distributed in any
 * form or by any means without prior explicit permission in writing from
 * Sony Semiconductor Solutions Corporation.
 *
 */

#ifndef __SENSOR_AI_LIB_STATE_H__
#define __SENSOR_AI_LIB_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** State value */
typedef enum {
    kSsfSensorLibStateStandby,
    kSsfSensorLibStateReady,
    kSsfSensorLibStateRunning,
    kSsfSensorLibStateFwUpdate,
    kSsfSensorLibStateUnknown,
} SsfSensorLibState;

/**
 * @brief Get the state of lib
 * @return State code.
 */
SsfSensorLibState SsfSensorLibGetState(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SENSOR_AI_LIB_STATE_H__ */
