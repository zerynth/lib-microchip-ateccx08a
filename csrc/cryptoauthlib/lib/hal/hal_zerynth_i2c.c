/**
 * \file
 * \brief ATCA Hardware abstraction layer for SAMD21 I2C over ASF drivers.
 *
 * This code is structured in two parts.  Part 1 is the connection of the ATCA HAL API to the physical I2C
 * implementation. Part 2 is the ASF I2C primitives to set up the interface.
 *
 * Prerequisite: add SERCOM I2C Master Polled support to application in Atmel Studio
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#include "zerynth.h"

#include "atca_hal.h"
#include "hal_zerynth_i2c.h"
#include "atca_device.h"
#include "atca_execution.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 * using I2C driver of ASF.
 *
   @{ */

/** \brief logical to physical bus mapping structure */
ATCAI2CMaster_t i2c_hal_data[MAX_I2C_BUSES];   // map logical, 0-based bus number to index
int i2c_bus_ref_ct = 0;                         // total in-use count across buses
// static struct i2c_master_config config_i2c_master;

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{

    /* if every SERCOM was a likely candidate bus, then would need to initialize the entire array to all SERCOM n numbers.
     * As an optimization and making discovery safer, make assumptions about bus-num / SERCOM map based on D21 Xplained Pro board
     * If you were using a raw D21 on your own board, you would supply your own bus numbers based on your particular hardware configuration.
     */
    int i;
    for (i=0; i<max_buses; i++) {
        i2c_buses[i] = i;
    }

    return ATCA_SUCCESS;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in]  busNum  logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg     pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] found   number of devices found on this bus
 * \return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found)
{
    (void) busNum;
    (void) cfg;
    (void) found;
    // NOT IMPLEMENTED

    return ATCA_SUCCESS;
}

/** \brief
    - this HAL implementation assumes you've included the ASF SERCOM I2C libraries in your project, otherwise,
    the HAL layer will not compile because the ASF I2C drivers are a dependency *
 */

/** \brief hal_i2c_init manages requests to initialize a physical interface.  it manages use counts so when an interface
 * has released the physical layer, it will disable the interface for some other use.
 * You can have multiple ATCAIFace instances using the same bus, and you can have multiple ATCAIFace instances on
 * multiple i2c buses, so hal_i2c_init manages these things and ATCAIFace is abstracted from the physical details.
 */

/** \brief initialize an I2C interface using given config
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    (void) hal;

    int bus = cfg->atcai2c.bus;   // 0-based logical bus number

    i2c_bus_ref_ct++;  // total across buses

    if (bus >= 0 && bus < MAX_I2C_BUSES)
    {
        // if this is the first time this bus and interface has been created, do the physical work of enabling it
        if (i2c_hal_data[bus].ref_ct == 0)
        {
            
            vhalI2CConf conf;
            conf.clock = cfg->atcai2c.baud;
            conf.addr = (uint16_t)cfg->atcai2c.slave_address; // >> 1 ?
            I2CPins *i2cpins = ((I2CPins*)_vm_pin_map(PRPH_I2C));
            conf.sda = i2cpins[bus].sda;
            conf.scl = i2cpins[bus].scl;
            int status = vhalI2CInit(bus, &conf);

            if (status < 0) {
                return ATCA_COMM_FAIL;
            }

            i2c_hal_data[bus].ref_ct = 1;
            i2c_hal_data[bus].bus_index = bus;

        }
        else
        {
            // otherwise, another interface already initialized the bus, so this interface will share it and any different
            // cfg parameters will be ignored...first one to initialize this sets the configuration
            i2c_hal_data[bus].ref_ct++;
        }

        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    (void) iface;

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send over ASF
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;

    // for this implementation of I2C with CryptoAuth chips, txdata is assumed to have ATCAPacket format

    // other device types that don't require i/o tokens on the front end of a command need a different hal_i2c_send and wire it up instead of this one
    // this covers devices such as ATSHA204A and ATECCx08A that require a word address value pre-pended to the packet
    // txdata[0] is using _reserved byte of the ATCAPacket
    txdata[0] = 0x03;   // insert the Word Address Value, Command token
    txlength++;         // account for word address value byte.
    // packet.data_length = txlength;


    vhalI2CSetAddr(bus,(uint16_t)cfg->atcai2c.slave_address);

    int timeout = 500;
    int code = vhalI2CTransmit(bus,txdata,txlength,NULL,0,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS));
    if (code < 0) {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function for ASF I2C
 * \param[in] iface     instance
 * \param[out] rxdata    pointer to space to receive the data
 * \param[in] rxlength  ptr to expected number of receive bytes to request
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    int status = -1;

    vhalI2CSetAddr(bus,(uint16_t)cfg->atcai2c.slave_address);
    int timeout = 100;

    while (retries-- > 0 && status < 0)
    {
        status = vhalI2CRead(bus,rxdata,*rxlength,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS));
    }

    if (status < 0)
    {
        return ATCA_COMM_FAIL;
    }

    if (atCheckCrc(rxdata) != ATCA_SUCCESS)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief method to change the bus speec of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */

void change_i2c_speed(ATCAIface iface, uint32_t speed)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;

    vhalI2CDone(bus);

    vhalI2CConf conf;
    conf.clock = speed;
    conf.addr = (uint16_t)cfg->atcai2c.slave_address; // >> 1 ?
    I2CPins *i2cpins = ((I2CPins*)_vm_pin_map(PRPH_I2C));
    conf.sda = i2cpins[bus].sda;
    conf.scl = i2cpins[bus].scl;
    vhalI2CInit(bus, &conf);

}


/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;

#ifdef ZERYNTH_HWCRYPTO_ATECCx08A_CUSTOM_WAKE
    return custom_hal_i2c_wake(bus, retries);
#else

    uint32_t bdrt = cfg->atcai2c.baud;
    int status = -1;
    uint8_t data[4], expected[4] = { 0x04, 0x11, 0x33, 0x43 };

    vhalI2CDone(bus);

    I2CPins *i2cpins = ((I2CPins*)_vm_pin_map(PRPH_I2C));
    int sdapin = i2cpins[bus].sda;

    vhalPinSetMode(sdapin, PINMODE_OUTPUT_PUSHPULL);
    vhalPinWrite(sdapin, 0);

    atca_delay_ms(1);

    vhalPinWrite(sdapin, 1);

    atca_delay_ms(2);

    if (bdrt != 100000) {
        // if not already at 100KHz, change it
        change_i2c_speed(iface, 100000);
    }

    // init
    vhalI2CConf conf;
    conf.clock = 100000;
    conf.addr = (uint16_t)cfg->atcai2c.slave_address;
    conf.sda = i2cpins[bus].sda;
    conf.scl = i2cpins[bus].scl;
    vhalI2CInit(bus, &conf);

    int timeout = 100;

    while (retries-- > 0 && status < 0) {
        status = vhalI2CRead(bus,data,4,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS));
    }

    if (status < 0) {
        return ATCA_COMM_FAIL;
    }

    if (memcmp(data, expected, 4) == 0) {
        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;

#endif
}

#if 0
// pure i2c implementation, less reliable
ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    uint32_t bdrt = cfg->atcai2c.baud;
    int status = -1;
    uint8_t data[4], expected[4] = { 0x04, 0x11, 0x33, 0x43 };

    if (bdrt != 100000)    // if not already at 100KHz, change it
    {
        change_i2c_speed(iface, 100000);
    }

    // Send the wake by writing to an address of 0x00
    vhalI2CSetAddr(bus,(uint16_t)0);
    int timeout = 100;
    vhalI2CTransmit(bus,data,1,NULL,0,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS)); // part will NACK, so don't check for status

    atca_delay_ms(1);
    // atca_delay_us(cfg->wake_delay);                                                         // wait tWHI + tWLO which is configured based on device type and configuration structure

    vhalI2CSetAddr(bus,(uint16_t)cfg->atcai2c.slave_address);
    timeout = 100;

    while (retries-- > 0 && status < 0)
    {
        status = vhalI2CRead(bus,data,4,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS));
    }

    // if necessary, revert baud rate to what came in.
    if (bdrt != 100000)
    {
        change_i2c_speed(iface, bdrt);
    }

    if (status < 0)
    {
        return ATCA_COMM_FAIL;
    }

    if (memcmp(data, expected, 4) == 0)
    {
        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}
#endif

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];

    data[0] = 0x02;  // idle word address value

    vhalI2CSetAddr(bus,(uint16_t)cfg->atcai2c.slave_address);
    int timeout = 500;
    if (vhalI2CTransmit(bus,data,1,NULL,0,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];

    data[0] = 0x01;  // sleep word address value

    vhalI2CSetAddr(bus,(uint16_t)cfg->atcai2c.slave_address);
    int timeout = 500;
    if (vhalI2CTransmit(bus,data,1,NULL,0,(timeout<0) ? (VTIME_INFINITE):TIME_U(timeout,MILLIS)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    i2c_bus_ref_ct--;  // track total i2c bus interface instances for consistency checking and debugging

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0)
    {
        vhalI2CDone(hal->bus_index);
        i2c_hal_data[hal->bus_index].ref_ct    = 0;
        i2c_hal_data[hal->bus_index].bus_index = 0;
    }

    return ATCA_SUCCESS;
}

/** @} */
