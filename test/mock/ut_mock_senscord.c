/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_core_init(senscord_core_t *core)
{
    check_expected_ptr(core);

#ifdef INITIAL_SETTING_APP_PS
    *core = mock_type(senscord_core_t);
#endif

    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_core_open_stream(senscord_core_t core, const char *stream_key,
                                         senscord_stream_t *stream)
{
    check_expected(core);
    check_expected_ptr(stream_key);
    check_expected(stream);

#ifdef INITIAL_SETTING_APP_PS
    *stream = mock_type(senscord_stream_t);
#endif

    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_get_property(senscord_stream_t stream, const char *property_key,
                                            void *value, size_t value_size)
{
    check_expected(stream);
    check_expected_ptr(property_key);
    check_expected(value_size);

    if (strcmp(property_key, SENSCORD_IMAGE_PROPERTY_KEY) == 0) {
        *(struct senscord_image_property_t *)value =
            *(mock_type(struct senscord_image_property_t *));
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY) == 0) {
        struct senscord_register_access_8_property_t *register_access_8 =
            (struct senscord_register_access_8_property_t *)value;
        check_expected(register_access_8->id);
        check_expected(register_access_8->address);
        register_access_8->data = mock_type(uint8_t);
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY) == 0) {
        struct senscord_register_access_16_property_t *register_access_16 =
            (struct senscord_register_access_16_property_t *)value;
        check_expected(register_access_16->id);
        check_expected(register_access_16->address);
        register_access_16->data = mock_type(uint16_t);
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY) == 0) {
        struct senscord_register_access_32_property_t *register_access_32 =
            (struct senscord_register_access_32_property_t *)value;
        check_expected(register_access_32->id);
        check_expected(register_access_32->address);
        register_access_32->data = mock_type(uint32_t);
    }
    else if (strcmp(property_key, SENSCORD_CAMERA_AUTO_EXPOSURE_METERING_PROPERTY_KEY) == 0) {
        struct senscord_camera_auto_exposure_metering_property_t
            *senscord_camera_auto_exposure_metering =
                (struct senscord_camera_auto_exposure_metering_property_t *)value;
        senscord_camera_auto_exposure_metering->mode =
            mock_type(enum senscord_camera_auto_exposure_metering_mode_t);
        senscord_camera_auto_exposure_metering->window.top = mock_type(uint32_t);
        senscord_camera_auto_exposure_metering->window.left = mock_type(uint32_t);
        senscord_camera_auto_exposure_metering->window.bottom = mock_type(uint32_t);
        senscord_camera_auto_exposure_metering->window.right = mock_type(uint32_t);
    }
    else {
        memcpy(value, mock_type(void *), value_size);
    }

    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_core_close_stream(senscord_core_t core, senscord_stream_t stream)
{
    check_expected(core);
    check_expected(stream);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_core_exit(senscord_core_t core)
{
    check_expected(core);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_start(senscord_stream_t stream)
{
    check_expected(stream);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_stop(senscord_stream_t stream)
{
    check_expected(stream);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_set_property(senscord_stream_t stream, const char *property_key,
                                            const void *value, size_t value_size)
{
    check_expected(stream);
    check_expected_ptr(property_key);
    //check_expected_ptr(value);
    check_expected(value_size);

    if (strcmp(property_key, SENSCORD_AI_MODEL_BUNDLE_ID_PROPERTY_KEY) == 0) {
        struct senscord_ai_model_bundle_id_property_t *ai_model =
            (struct senscord_ai_model_bundle_id_property_t *)value;
        check_expected_ptr(ai_model->ai_model_bundle_id);
    }
    else if (strcmp(property_key, SENSCORD_CAMERA_IMAGE_FLIP_PROPERTY_KEY) == 0) {
        struct senscord_camera_image_flip_property_t *flip_data =
            (struct senscord_camera_image_flip_property_t *)value;
        check_expected(flip_data->flip_horizontal);
        check_expected(flip_data->flip_vertical);
    }
    else if (strcmp(property_key, SENSCORD_INPUT_DATA_TYPE_PROPERTY_KEY) == 0) {
        struct senscord_input_data_type_property_t *input_data =
            (struct senscord_input_data_type_property_t *)value;
        check_expected(input_data->count);
        check_expected_ptr(input_data->channels[0]);
    }
    else if (strcmp(property_key, SENSCORD_IMAGE_CROP_PROPERTY_KEY) == 0) {
        struct senscord_image_crop_property_t *crop =
            (struct senscord_image_crop_property_t *)value;
        check_expected(crop->left);
        check_expected(crop->top);
        check_expected(crop->width);
        check_expected(crop->height);
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_8_PROPERTY_KEY) == 0) {
        struct senscord_register_access_8_property_t *senscord_register =
            (struct senscord_register_access_8_property_t *)value;
        check_expected(senscord_register->id);
        check_expected(senscord_register->address);
        check_expected(senscord_register->data);
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_16_PROPERTY_KEY) == 0) {
        struct senscord_register_access_16_property_t *senscord_register =
            (struct senscord_register_access_16_property_t *)value;
        check_expected(senscord_register->id);
        check_expected(senscord_register->address);
        check_expected(senscord_register->data);
    }
    else if (strcmp(property_key, SENSCORD_REGISTER_ACCESS_32_PROPERTY_KEY) == 0) {
        struct senscord_register_access_32_property_t *senscord_register =
            (struct senscord_register_access_32_property_t *)value;
        check_expected(senscord_register->id);
        check_expected(senscord_register->address);
        check_expected(senscord_register->data);
    }
    else if (strcmp(property_key, SENSCORD_CAMERA_AUTO_EXPOSURE_PROPERTY_KEY) == 0) {
        struct senscord_camera_auto_exposure_property_t *senscord_camera_auto_exposure =
            (struct senscord_camera_auto_exposure_property_t *)value;
        check_expected(senscord_camera_auto_exposure->max_exposure_time);
        //check_expected(senscord_camera_auto_exposure->min_exposure_time);
        //check_expected(senscord_camera_auto_exposure->max_gain);
        //check_expected(senscord_camera_auto_exposure->convergence_speed);
    }
    else if (strcmp(property_key, SENSCORD_CAMERA_AUTO_EXPOSURE_METERING_PROPERTY_KEY) == 0) {
        struct senscord_camera_auto_exposure_metering_property_t
            *senscord_camera_auto_exposure_metering =
                (struct senscord_camera_auto_exposure_metering_property_t *)value;
        check_expected(senscord_camera_auto_exposure_metering->mode);
        check_expected(senscord_camera_auto_exposure_metering->window.top);
        check_expected(senscord_camera_auto_exposure_metering->window.left);
        check_expected(senscord_camera_auto_exposure_metering->window.bottom);
        check_expected(senscord_camera_auto_exposure_metering->window.right);
    }
    else {
        // Invalid property_key Do Nothing
    }

    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_get_frame(senscord_stream_t stream, senscord_frame_t *frame,
                                         int32_t timeout_msec)
{
    check_expected(stream);
    check_expected(timeout_msec);
    *frame = mock_type(senscord_frame_t);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_stream_release_frame(senscord_stream_t stream, senscord_frame_t frame)
{
    check_expected(stream);
    check_expected(frame);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_channel_get_raw_data(senscord_channel_t channel,
                                             struct senscord_raw_data_t *raw_data)
{
    check_expected(channel);
    *raw_data = *(mock_type(struct senscord_raw_data_t *));
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
int32_t __wrap_senscord_frame_get_channel_from_channel_id(senscord_frame_t frame,
                                                          uint32_t channel_id,
                                                          senscord_channel_t *channel)
{
    check_expected(frame);
    check_expected(channel_id);
    *channel = mock_type(senscord_channel_t);
    return mock_type(int32_t);
}

/*----------------------------------------------------------------------------*/
enum senscord_error_cause_t __wrap_senscord_get_last_error_cause(void)
{
    return mock_type(enum senscord_error_cause_t);
}

/*----------------------------------------------------------------------------*/
