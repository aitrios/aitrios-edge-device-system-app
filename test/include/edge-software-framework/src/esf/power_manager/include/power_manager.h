/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef ESF_POWER_MANAGER_POWER_MANAGER_H_
#define ESF_POWER_MANAGER_POWER_MANAGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// An enumerated type that defines the result of API execution.
typedef enum EsfPwrMgrError {
  kEsfPwrMgrOk,                      // Processing Success.
  kEsfPwrMgrErrorInvalidArgument,    // Argument error.
  kEsfPwrMgrErrorResourceExhausted,  // Insufficient memory error.
  kEsfPwrMgrErrorInternal,           // Internal processing error.
  kEsfPwrMgrErrorAlreadyRunning,     // Return value during processing.
  kEsfPwrMgrErrorStatus,             // State error.
  kEsfPwrMgrErrorExternal,           // External API execution error.
  kEsfPwrMgrErrorTimeout,            // Timeout occurred.
  kEsfPwrMgrErrorUnsupportedApi,     // Unsupported API
  kEsfPwrMgrErrorWaitReboot,         // Wait WDT Ignition
} EsfPwrMgrError;

typedef enum EsfPwrMgrSupplyType {
  kEsfPwrMgrSupplyTypeUnknown = -1,
  kEsfPwrMgrSupplyTypePoE,
  kEsfPwrMgrSupplyTypeUsb,
  kEsfPwrMgrSupplyTypeDcPlug,
  kEsfPwrMgrSupplyTypePrimaryBattery,
  kEsfPwrMgrSupplyTypeSecondaryBattery,
  kEsfPwrMgrSupplyTypeMax
} EsfPwrMgrSupplyType;

// A define periodic addition cycle (in hours) for HoursMeter.
#define ESF_POWER_MANAGER_HOURS_METER_ADD_INTERVAL (1)

// """Start Power Manager.

// Description: Initializes the internal state.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorInternal: Internal processing error.
//    kEsfPwrMgrErrorExternal: Error in ParameterStorageManager operation.
//    kEsfPwrMgrErrorExternal: Error occurs in HAL operation.
EsfPwrMgrError EsfPwrMgrStart(void);

// """Exit Power Manager.

// Description: Internal state is set to Stop state.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorInternal: Internal processing error.
//    kEsfPwrMgrErrorExternal: Error in ParameterStorageManager operation.
//    kEsfPwrMgrErrorExternal: Error occurs in HAL operation.
EsfPwrMgrError EsfPwrMgrStop(void);

// """Exit Power Manager and wait WDT Ignition.

// Description: Internal state is set to Stop state.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorInternal: Internal processing error.
//    kEsfPwrMgrErrorExternal: Error in ParameterStorageManager operation.
//    kEsfPwrMgrErrorExternal: Error occurs in PL operation.
EsfPwrMgrError EsfPwrMgrStopForReboot(void);

// """Initiate system reboot.

// Description:
// Notifies SSF(main) of a restart event and notifies it of the opportunity to
// execute the necessary processing.
// Notify SSF(Led Manager) of the status change.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorAlreadyRunning: Return value during processing.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
EsfPwrMgrError EsfPwrMgrPrepareReboot(void);

// """Perform a system reboot.

// Description:
// HAL(SystemControl) to perform a system reboot.
// This API can be executed even when Power Manager is stopped.
// If this API is successful, the device will be restarted and will not respond.

// Args:
//    void

// Returns:
//    None.
void EsfPwrMgrExecuteReboot(void);

// """Initiate system shutdown.

// Description:
// Notifies SSF(main) of the shutdown and notifies it of the opportunity to
// execute the required process.
// Notify SSF(Led Manager) of the status change.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorAlreadyRunning: Return value during processing.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
EsfPwrMgrError EsfPwrMgrPrepareShutdown(void);

// """Perform a system shutdown.

// Description:
// HAL(SystemControl) to perform a system shutdown.
// This API can be executed even when Power Manager is stopped.
// If this API is successful, the device will be restarted and will not respond.

// Args:
//    void

// Returns:
//    None.
void EsfPwrMgrExecuteShutdown(void);

// """Obtains operating voltage information.

// Description:
// Obtains operating voltage information from HAL(T.B.D) and responds.

// Args:
//    [OUT] voltage(int32_t *) : Operating voltage information.
//                               NULL is not acceptable.

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorInvalidArgument: Argument error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
EsfPwrMgrError EsfPwrMgrGetVoltage(int32_t *voltage);

// """Get current value of Hours meter.

// Description: Retrieve and respond to Hours meter.

// Args:
//    [OUT] hours (int32_t *): Current value of Hours meter.
//                             NULL is not acceptable.

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorInvalidArgument: Argument error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
EsfPwrMgrError EsfPwrMgrHoursMeterGetValue(int32_t *hours);

// """Terminate WDT

// Description: Call WDT Terminate API.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
EsfPwrMgrError EsfPwrMgrWdtTerminate(void);

// """Get current Supply Type

// Description: Call Get Supply Type API.

// Args:
//    [OUT] supply_type (EsfPwrMgrSupplyType *): Current Supply Type.
//                                               NULL is not acceptable.

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorInvalidArgument: Argument error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
//    kEsfPwrMgrErrorUnsupportedApi: Not support api error
EsfPwrMgrError EsfPwrMgrGetSupplyType(EsfPwrMgrSupplyType *supply_type);

// """Send KeepAlive to WDT

// Description: Send KeepAlive to WDT.

// Args:
//    void

// Returns:
//    kEsfPwrMgrOk: Processing Success.
//    kEsfPwrMgrErrorStatus: State error.
//    kEsfPwrMgrErrorTimeout: Timeout occurred.
//    kEsfPwrMgrErrorExternal: External API execution error.
//    kEsfPwrMgrErrorInternal: Internal processing error.
EsfPwrMgrError EsfPwrMgrWdtKeepAlive(void);

#ifdef __cplusplus
}
#endif

#endif  // ESF_POWER_MANAGER_POWER_MANAGER_H_
