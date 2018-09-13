/*
* @Author: Lorenzo
* @Date:   2018-08-31 16:08:27
* @Last Modified by:   Lorenzo
* @Last Modified time: 2018-09-03 10:33:37
*/

#define ZERYNTH_PRINTF
#include "zerynth.h"
#include "atca_command.h"

typedef struct {
    uint8_t  opcode;
    uint16_t execution_time_msec_typ;
    uint16_t execution_time_msec_max;
} device_execution_time_t;

static const device_execution_time_t device_execution_time_508[] = {
    { ATCA_CHECKMAC,      5,  13},
    { ATCA_COUNTER,       5,  20},
    { ATCA_DERIVE_KEY,    2,  50},
    { ATCA_ECDH,         38,  58},
    { ATCA_GENDIG,        5,  11},
    { ATCA_GENKEY,       11, 115},
    { ATCA_HMAC,         13,  23},
    { ATCA_INFO,          1,   2},
    { ATCA_LOCK,          8,  32},
    { ATCA_MAC,           5,  14},
    { ATCA_NONCE,         1,  29},
    { ATCA_PAUSE,         1,   3},
    { ATCA_PRIVWRITE,     1,  48},
    { ATCA_RANDOM,        1,  23},
    { ATCA_READ,          1,   5},
    { ATCA_SHA,           7,   9},
    { ATCA_SIGN,         42,  60},
    { ATCA_UPDATE_EXTRA,  8,  10},
    { ATCA_VERIFY,       38,  72},
    { ATCA_WRITE,         7,  26}
};

static const device_execution_time_t device_execution_time_608[] = {
    { ATCA_AES,           1,  27},
    { ATCA_CHECKMAC,      8,  40},
    { ATCA_COUNTER,       1,  25},
    { ATCA_DERIVE_KEY,   15,  50},
    { ATCA_ECDH,         28, 455},
    { ATCA_GENDIG,       11,  35},
    { ATCA_GENKEY,       59, 630},
    { ATCA_INFO,          1,   5},
    { ATCA_KDF,          99, 165},
    { ATCA_LOCK,         15,  35},
    { ATCA_MAC,           7,  55},
    { ATCA_NONCE,        17,  20},
    { ATCA_PRIVWRITE,    29,  50},
    { ATCA_RANDOM,       15,  23},
    { ATCA_READ,          1,   5},
    { ATCA_SECUREBOOT,    1, 451},
    { ATCA_SELFTEST,    110,2200},
    { ATCA_SHA,           1,  75},
    { ATCA_SIGN,         60, 665},
    { ATCA_UPDATE_EXTRA,  8,  10},
    { ATCA_VERIFY,       27,1085},
    { ATCA_WRITE,         8,  45}
};


C_NATIVE(_ateccx08a_get_exec_time) {
    NATIVE_UNWARN();

    uint32_t opcode, devtype;
    uint16_t execution_time_msec_typ_max[2];

    const device_execution_time_t *execution_times;
    uint8_t i, no_of_commands;

    if (parse_py_args("ii", nargs, args, &opcode, &devtype) != 2)
        return ERR_TYPE_EXC;


    switch (devtype) {
        case ATECC508A:
            execution_times = device_execution_time_508;
            no_of_commands = sizeof(device_execution_time_508) / sizeof(device_execution_time_t);
            break;

        case ATECC608A:
            execution_times = device_execution_time_608;
            no_of_commands = sizeof(device_execution_time_608) / sizeof(device_execution_time_t);
            break;

        default:
            return ERR_VALUE_EXC;
    }

    execution_time_msec_typ_max[0] = 0xFFFF;

    for (i = 0; i < no_of_commands; i++) {
        if (execution_times[i].opcode == opcode) {
            execution_time_msec_typ_max[0] = execution_times[i].execution_time_msec_typ;
            execution_time_msec_typ_max[1] = execution_times[i].execution_time_msec_max;
            break;
        }
    }

    if (execution_time_msec_typ_max[0] == 0xFFFF) {
        return ERR_VALUE_EXC;
    }

    *res = pshorts_new(2, execution_time_msec_typ_max);
    return ERR_OK;
}

C_NATIVE(_ateccx08a_crc16) {
    NATIVE_UNWARN();

    uint8_t *data;
    uint32_t length, counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;
    uint8_t crc_le[2];

    // s instead of b to get len (actually filled elements) instead of size 
    if (parse_py_args("s", nargs, args, &data, &length) != 1)
        return ERR_TYPE_EXC;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
        {
            data_bit = (data[counter] & shift_register) ? 1 : 0;
            crc_bit = crc_register >> 15;
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }

    crc_le[0] = (uint8_t)(crc_register & 0x00FF);
    crc_le[1] = (uint8_t)(crc_register >> 8);

    *res = pbytes_new(2, crc_le);

    return ERR_OK;
}