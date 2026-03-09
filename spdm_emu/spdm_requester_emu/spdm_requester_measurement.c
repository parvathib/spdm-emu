/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

extern void *m_spdm_context;

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

/* Helper function to set nonce from environment variable */
void set_nonce_from_env(uint8_t *nonce_buffer)
{
    const char *env_nonce = getenv("SPDM_NONCE");
    if (env_nonce != NULL && strlen(env_nonce) == (SPDM_NONCE_SIZE * 2)) {
        /* Convert hex string to bytes */
        for (size_t i = 0; i < SPDM_NONCE_SIZE; i++) {
            char hex_byte[3] = {env_nonce[i*2], env_nonce[i*2+1], '\0'};
            nonce_buffer[i] = (uint8_t)strtol(hex_byte, NULL, 16);
        }
    } else {
        /* Use default/zero nonce if env var not set or invalid */
        libspdm_zero_mem(nonce_buffer, SPDM_NONCE_SIZE);
    }
}

void write_certificate_chain_to_file(uint8_t *cert_chain_buffer, size_t cert_chain_size, uint8_t slot_id)
{
    FILE *file;
    char file_name[64];
    uint32_t cert_start = 52; /*SPDM cert chain metadata size - fixed for SHA384*/

    snprintf(file_name, sizeof(file_name), "certificate_chain_slot_%02x.der", slot_id);
    file = fopen(file_name, "wb");
    if (file != NULL)
    {
        /* Skip SPDM metadata and write only the certificate chain */
        if (cert_chain_size > cert_start) {
            fwrite(cert_chain_buffer + cert_start, 1, cert_chain_size - cert_start, file);
            printf("Certificate chain written to %s (size: %zu bytes, skipped %u bytes metadata)\n",
                   file_name, cert_chain_size - cert_start, cert_start);
        } else {
            /* If size is too small, write the whole buffer */
            fwrite(cert_chain_buffer, 1, cert_chain_size, file);
            printf("Certificate chain written to %s (size: %zu bytes, no metadata skipped)\n",
                   file_name, cert_chain_size);
        }
        fclose(file);
    }
}

void write_measurement_block_to_file(uint8_t *measurement_block,
                                     uint32_t measurement_block_length, uint8_t index)
{
    FILE *file;
    char file_name[64];

    uint8_t metadata_size = sizeof(spdm_measurement_block_common_header_t) + sizeof(spdm_measurement_block_dmtf_header_t);

    uint8_t *measurement_block_value = measurement_block + metadata_size;
    snprintf(file_name, sizeof(file_name), "measurement_block_%02x.bin", index);
    file = fopen(file_name, "wb");
    if (file != NULL)
    {
        fwrite(measurement_block_value, 1, measurement_block_length - metadata_size, file);
        fclose(file);
    }
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id)
{
    libspdm_return_t status;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    uint32_t data32;
    size_t data_size;
    bool need_sig;
    libspdm_data_parameter_t parameter;
    uint8_t requester_context[SPDM_REQ_CONTEXT_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00};
    uint8_t nonce[SPDM_NONCE_SIZE];

    /*get requester_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) != 0) {
        need_sig = false;
    } else {
        need_sig = true;
    }

    if (m_use_measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* request all at one time.*/
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] =
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
        if (need_sig) {
            request_attribute =
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            request_attribute = 0;
        }
        measurement_record_length = sizeof(measurement_record);
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
            &measurement_record_length, measurement_record,
            NULL, NULL, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else {
        /* Set nonce from environment variable */
        set_nonce_from_env(nonce);

        /* request all measurements at once using index 0xFD */
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] = 0xFD;
        if (need_sig) {
            request_attribute = m_use_measurement_attribute |
                                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            request_attribute = m_use_measurement_attribute;
        }
        measurement_record_length = sizeof(measurement_record);
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            0xFD,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
            &measurement_record_length, measurement_record,
            nonce, NULL, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        write_measurement_block_to_file(measurement_record, measurement_record_length, 0xFD);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;

    spdm_context = m_spdm_context;

    status = spdm_send_receive_get_measurement(spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement MEL.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_mel_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    libspdm_data_parameter_t parameter;
    uint32_t measurement_hash_algo;
    size_t data_size;

    spdm_context = m_spdm_context;
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    /* get setting from connection*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(measurement_hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &measurement_hash_algo, &data_size);

    status = libspdm_get_measurement_extension_log(spdm_context, session_id, &spdm_mel_size,
                                                   spdm_mel);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
