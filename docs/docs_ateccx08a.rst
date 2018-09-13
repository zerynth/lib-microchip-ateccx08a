.. module:: ateccx08a

*****************
ATECCx08A library
*****************

This module exports classes for Microchip ATECCx08A chip family and some utilities functions.

Furthermore an interface to allow the use of chip-related functionalities from other Zerynth hybrid C/Python libraries is made available.

    
=================
Auxiliary methods
=================

..  function:: crc16(data: bytes)

    Compute the CRC16 checksum for some bytes.
    The CRC is calculated using 0x8005 as polynomial and starting with the registry set as 0x00.

    :param data: bytes to be checksummed.
    :type data: bytes
    :returns: 2 bytes, representing the computed checksum.
    :rtype: bytes
    
=============
ATECC508A class
=============

..  class:: ATECC508A(i2c.I2C)

    Class for controlling the ATECC508A chip.

    Members:

    * device_awake : Boolean. If True the device is running a multiple commands sequence.
    
..  method:: __init__(drvname, addr=DEFAULT_ADDR, clk=100000)

    Connect to a device and start I2C protocol.

    :param drvname: Interface for I2C communication (e.g. I2C0)
    :param addr: Address of the I2C chip. (Default value = 0x60 for ATECC508A)
    :type addr: int [0-255]
    :param clk: Clock rate of the I2C communication in kHz. (Default value = 100000).
    :type clk: int
----------------
Internal methods
----------------

..  method:: _send_cmd(self, opcode, param1, param2: bytes, data=bytes())

    Send a command packet to the device.

    Output packet structure:
        [ 0x03 ][ length ][ opcode ][ p1 ][ p2 ][ ...data... ][ crc ]

        * 0x03 is a constant defined in `WORD_ADDRS` at the beginning of this module.
        * `length` includes every bytes except the first 0x03 byte.
        * `p1` is `byte` of length 1. (mandatory)
        * `p2` is `bytes` of length 2. (mandatory)
        * `data` is optional and can have arbitraty length.
        * `crc` is a 2 byte checksum (calculated using :meth:`ecc508a.crc16`).

    :param opcode: The code representing the selected command.
        Check `OPCODES` at the beginning of this module.
    :type opcode: int
    :param param1: The first mandatory parameter. 1 byte long.
    :type param1: int
    :param param2: The second mandatory parameter. 2 bytes long.
    :type param2: bytes
    :param data: Other optional data. (Default value = bytes())
    :type data: bytes
..  method:: _read_result()

    Read, verify checksum, and extract data of a packet from the device.

    Input packet structure:
        [ length ][ ...data... ][ crc ]

    :returns: the extracted data bytes.
    :rtype: bytes

    Note:
        Length includes itself (1 byte), data (n bytes), and crc16 (2 bytes).
--------------
Public methods
--------------
..  method:: start_cmd_sequence()

    Call this function before a command sequence to wake up device from idle mode.

    This is done by keeping SDA low for more than 60 microseconds.

    Note:
        At this moment a 0x00 byte is written as a normal I2C transaction, ignoring
        the exception raised.
        This workaround won't work at higher clock rates (more than ~100 kHz)!
        
..  method:: end_cmd_sequence()

    Call this function at the end of a command sequence to put the device in idle mode.

    This must be done in order to avoid hitting the watchdog timeout (~1 second) which will
    put the device in idle mode no matter what.
        
..  method:: send_and_read(*args)

    Send a command and return the result data.

    Note:
        If :meth:`start_cmd_sequence()` was not invoked before this method, the device
        is automatically woke up and put again in idle mode after the command execution.
        (Default value = 50)

    :param *args: All arguments are passed to :meth:`._send_cmd` method.
    :type exec_time: int
--------
Commands
--------

The functions names are the lowercase command name followed by `_cmd`.
Parameters are command specific.

A command usually return some bytes as the result of the command execution, or a status
code.

..  method:: checkmac_cmd(tempkey_as_message_source: bool, tempkey_as_first_block: bool,                source_flag: int, key_id: bytes, challenge: bytes, response: bytes,                other_data: bytes)

    Verify a MAC calculated on another CryptoAuthentication device.

    :param tempkey_as_message_source: If False the second 32 bytes of the SHA message
            are taken from `challenge` parameter, otherwise they are taken from TempKey.
    :type tempkey_as_message_source: bool
    :param tempkey_as_first_block: If False Slot<KeyID> in first SHA block is used,
            otherwise TempKey is.
    :type tempkey_as_first_block: bool
    :param source_flag: Single bit. If `tempkey_as_message_source` or
            `tempkey_as_first_block` are set to True, then the value of this bit must match
            the value in TempKey.SourceFlag or the command will return an error.
            The flag is the fourth bit returned by `info_cmd('State')`.
    :type source_flag: int
    :param key_id: Internal key used to generate the response. All except last four
            bits are ignored.
    :type key_id: bytes
    :param challenge: 32 bytes, challenge sent to client.
            If `tempkey_as_message_source` is True, this parameter will be ignored.
    :type challenge: bytes
    :param response: 32 bytes, response generated by the client.
    :type response: bytes
    :param other_data: 13 bytes, remaining constant data needed for response
            calculation.
    :type other_data: bytes
    :returns: True if `response` matches the computed digest, False otherwise.
    :rtype: bool
..  method:: read_counter_cmd(key_id)

    Read one of the two monotonic counters.

    :param key_id: The specified counter. Can be 0 or 1.
    :type key_id: int

    :returns: 4 bytes representing the current value of the counter, or 1 byte representing
        a status code.
    :rtype: bytes
..  method:: inc_counter_cmd(key_id)

    Increment one of the two monotonic counters.

    The maximum value that the counter may have is 2,097,151.
    Any attempt to count beyond this value will result in an error code.

    :param key_id: The specified counter. Can be 0 or 1.
    :type key_id: int

    :returns: 4 bytes representing the current value of the counter, or 1 byte representing
        a status code.
    :rtype: bytes
..  method:: derivekey_cmd(source_flag: int, target_key: bytes, mac=bytes())

    The device combines the current value of a key with the nonce stored in TempKey using
    SHA-256 and places the result into the target key slot.

    Prior to execution of this command, :meth:`.nonce_cmd()` must have been run to
    create a valid nonce in TempKey.

    For full documentation check datasheet at pages 63-64.

    :param source_flag: Single bit (1 or 0). The value of this bit must match the value
            in TempKey.SourceFlag or the command will return an error.
            The flag is the fourth bit returned by :meth:`.info_cmd`.
    :type source_flag: int
    :param target_key: 2 bytes. Key slot to be written.
    :type target_key: bytes
    :param mac: MAC used to validate the operation. (Default value = bytes())
    :type mac: bytes

    :returns: True if the operation completed successfully.
    :rtype: bool
..  method:: ecdh_cmd(key_id: bytes, x_comp: bytes, y_comp: bytes)

    Generate an ECDH master secret using stored private key and input public key.

    :param key_id: The private key to be used in the ECDH calculation.
    :type key_id: bytes
    :param x_comp: The X component of the public key to be used for ECDH calculation.
    :type x_comp: bytes
    :param y_comp: The Y component of the public key to be used for ECDH calculation.
    :type y_comp: bytes

    :returns: If any error occured, the error code.
        If specified by SlotConfig.ReadKey<3>, the shared secret.
        Otherwise the success code 0x00.

    :rtype: bytes
..  method:: gendig_cmd(self, zone: int, key_id: bytes, other_data=bytes())

    Generate a data digest from a random or input seed and a key.

    See datasheet page 66-69 for full usage details.

    :param zone: Possible values are numbers between 0 and 5 (included).

            If 0x00 (Config), then use `key_id` to specify any of the four 256-bit blocks
            of the Configuration zone. If `key_id` has a value greater than three, the
            command will return an error.

            If 0x01 (OTP), use `key_id` to specify either the first or second 256-bit block
            of the OTP zone.

            If 0x02 (Data), then `key_id` specifies a slot in the Data zone or a transport
            key in the hardware array.

            If 0x03 (Shared Nonce), then `key_id` specifies the location of the input value
            in the message generation.

            If 0x04 (Counter), then `key_id` specifies the monotonic counter ID to be
            included in the message generation.

            If 0x05 (Key Config), then `key_id` specifies the slot for which the
            configuration information is to be included in the message generation.
    :type zone: int
    :param key_id: Identification number of the key to be used, selection of which OTP
            block or message order for Shared Nonce mode.
    :type key_id: bytes
    :param other_data: 4 bytes of data for SHA calculation when using a NoMac
            key, 32 bytes for "Shared Nonce" mode, otherwise ignored.
            (Default value = bytes())
    :type other_data: bytes

    :returns: True if the operation completed successfully.
    :rtype: bool
..  method:: gen_private_key(self, key_slot: int, create_digest=False,                other_data=bytes(3))

    Generate an ECC private key.

    :param key_slot: Specifies the slot where the private ECC key is generated.
    :type key_slot: bytes
    :param create_digest: If True the device creates a PubKey digest based on the
            private key in KeyID and places it in TempKey (ignored if `create_digest` is
            False).
    :type create_digest: bool
    :param other_data: 3 bytes, used in the creation of the message used as input for
            the digest algorithm.
    :type other_data: bytes

    :returns: 64 bytes representing public key X and Y coordinates or 1 byte representing
        a status code if an error occured.
    :rtype: bytes
..  method:: gen_public_key(self, key_slot: int, create_digest=False, other_data=bytes(3))

    Generate the ECC public key starting from a private key.

    :param key_slot: Specifies the slot where the private ECC key is.
    :type key_slot: int
    :param create_digest: If True the device creates a PubKey digest based on the
            private key in KeyID and places it in TempKey (ignored if `create_digest` is
            False).
    :type create_digest: bool
    :param other_data: 3 bytes, used in the creation of the message used as input for
            the digest algorithm.
    :type other_data: bytes

    :returns: 64 bytes representing public key X and Y coordinates or 1 byte representing
        a status code if an error occured.
    :rtype: bytes
..  method:: gen_digest_cmd(self, key_id: bytes, other_data: bytes)

    Generate a digest and store it in TempKey, using key_id as public key.

    :param key_id: Specifies the slot where the public ECC key is.
    :type key_id: bytes
    :param other_data: 3 bytes, used in the creation of the message used as input for
        the digest algorithm.
    :type other_data: bytes

    :returns: 64 bytes representing public key X and Y coordinates or 1 byte representing
        a status code if an error occured.
    :rtype: bytes
..  method:: hmac_cmd(self, source_flag: int, key_id: bytes, include_sn: bool)

    Calculate response from key and other internal data using HMAC/SHA-256.

    :param source_flag: Single bit. The value of this bit must match the value in
            TempKey.SourceFlag (1 = True, 0 = False) or the command will return an error.
            The flag is the fourth bit returned by `info_cmd('State')`.
    :type source_flag: int
    :param key_id: Specifies the slot where the key is.
            Note that while only last four bits are used to select a slot, all the two
            bytes will be included in the digest message.
    :type key_id: bytes
    :param include_sn: If True, 48 bits from Configuration Zone are included in the
            digest message.
    :type include_sn: bool

    :returns: 32 bytes, the computed HMAC digest.
    :rtype: bytes
..  method:: info_cmd(self, mode: str, param=bytes(2))

    Return device state information.
    The information read can be static or dynamic.

    :param zone: Zone to read byte from. The value is case insensitive and can be one of
        `Revision`, `KeyValid`, `State`, `GPIO`.
    :type zone: str
    :param param: Second parameter (Default value = bytes(2))
    :type param: bytes

    :returns: 4 bytes read from the device or 1 byte status code
    :rtype: bytes
..  method:: lock_config_zone_cmd(self, checksum: bytes=None)

    Prevent further modifications to the Config zone of the device.

    :param checksum: 2 bytes representing a CRC summary of the zone.
            If set the checksum is verified from the device prior locking.
            (Default value = None)
    :type checksum: bytes

    :returns: Single byte 0 if the operation completed successfully.
    :rtype: bytes
..  method:: lock_data_zone_cmd(checksum: bytes = None)

    Prevent further modifications to the Data and OTP zones of the device.

    :param checksum: 2 bytes representing a CRC summary of the zone.
            If set the checksum is verified from the device prior locking.
            (Default value = None)
    :type checksum: bytes

    :returns: Single byte 0 if the operation completed successfully.
    :rtype: bytes
.. method:: lock_single_slot_cmd(self, slot_number: int)

    Prevent further modifications to a single slot of the device.

    :param slot_number: Slot ID to be locked, valid values are the numbers in range 0-15
            (included).
    :type slot_number: int

    :returns: Single byte 0 if the operation completed successfully.
    :rtype: bytes
..  method:: mac_cmd(self, key_id: bytes, use_tempkey: bool, include_sn: bool,                source_flag: int = 0, challenge: bytes = bytes())

    Compute a SHA-256 digest from key and other internal data using SHA-256.

    The normal command flow to use this command is as follows:

        1. Run Nonce command to load input challenge and optionally combine it with a
        generated random number. The result of this operation is a nonce stored internally
        on the device.

        2. Optionally, run GenDig command to combine one or more stored EEPROM locations
        in the device with the nonce. The result is stored internally in the device.
        This capability permits two or more keys to be used as part of the response
        generation.

        3. Run this MAC command to combine the output of step one (and step two if desired)
        with an EEPROM key to generate an output response (i.e. digest).

    .. note:: `source_flag` MUST be specified if `use_tempkey` is True or a `challenge`
        is used.

    :param key_id: 2 bytes. Specifies the slot where the key is.
            Note that while only last four bits are used to select a slot, all the two
            bytes will be included in the digest message.
    :type key_id: bytes
    :param use_tempkey: If False the first 32 bytes of the SHA message are loaded from
            one of the data slots. Otherwise the first 32 bytes are filled with TempKey
            (and `source_flag` must be used).
    :type use_tempkey: bool
    :param include_sn: If True, 48 bits from Configuration Zone are included in the
            digest message.
    :type include_sn: bool
    :param source_flag: Single bit. The value of this bit must match the value
            in TempKey.SourceFlag (1 = True, 0 = False) or the command will return an error.
            The flag is the fourth bit returned by `info_cmd('State')`.
            (Default value = 0)
    :type source_flag: int
    :param challenge: 32 bytes. If specified, it will be used in the input
            of the algorithm. (Default value = bytes())
    :type challenge: bytes

    :returns: 32 bytes, the computed SHA-256 digest.
    :rtype: bytes
.. method:: nonce_cmd(self, use_tempkey: bool, num_in: bytes,                force_no_eeprom_update: bool = False)

    Generate a 32-byte random number and an internally stored Nonce.

    The body used to create the nonce is stored internally in TempKey.

    :param use_tempkey: TempKey is used instead of the RNG in the hash calculation input
            (message). TempKey is also returned by this command.
            TempKey must be valid prior to execution of this command and the values of the
            remaining TempKey flags remain unchanged.
    :type use_tempkey: bool
    :param num_in: 20 bytes, the input parameter.
    :type num_in: bytes
    :param force_no_eeprom_update: If True, the EEPROM is not updated before the RNG
            generation (the existing EEPROM is used, not recommended).
            (Default value = False)
    :type force_no_eeprom_update: bool

    :returns: TempKey (32 bytes) if `use_tempkey` is True. Otherwise the RNG output.
    :rtype: bytes
.. method:: nonce_passthrough_cmd(self, num_in: bytes)

    Pass-through mode of the Nonce command.

    TempKey is loaded with NumIn. No SHA-256 calculation is performed, and
    TempKey.SourceFlag is set to Input.
    (No data is returned to the system in this mode).

    :param num_in: 32 bytes, input parameter.
    :type num_in: bytes

    :returns: Single byte 0 if the operation completed successfully.
    :rtype: bytes
.. method:: privwrite_cmd(self, encrypt_input: bool, key_id: bytes, value: bytes,                mac: bytes)

    Write an ECC private key into a slot in the Data zone.

    For best security, PrivWrite should not be used, and private keys should be internally
    generated from the RNG using `gen_private_key` command.

    The slot indicated by this command must be configured via KeyConfig.Private to contain
    an ECC private key, and SlotConfig.IsSecret must be set to one.

    See datasheet page 80 for full details.

    :param encrypt_input: If True, the input data is encrypt using TempKey.
            Otherwise, the input data is not encrypted - this is valid only when Data zone
            is unlocked.
    :type encrypt_input: bool
    :param key_id: 2 bytes, slot id to be written.
    :type key_id: bytes
    :param value: 36 bytes integer. Information to be written to the slot, first 4
            bytes should be zero.
    :type value: bytes
    :param mac: 32 bytes. Message Authentication Code to validate EEPROM Write
            operation.
    :type mac: bytes

    :returns: Single byte 0 if the operation completed successfully.
    :rtype: bytes
.. method:: random_cmd(self, force_no_eeprom_update=False)

    Generate a random number.
    The number is generated using a seed stored in the EEPROM and a hardware RNG.

    :param force_no_eeprom_update: If True, the EEPROM is not updated before the RNG
            generation (the existing EEPROM is used, not recommended).
            (Default value = False)
    :type force_no_eeprom_update: bool

    :returns: 32 bytes, output of RNG.
        Prior to the configuration zone being locked, the RNG produces a value of
        0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 to facilitate testing.
    :rtype: bytes
.. method:: read_cmd(self, zone: str, address: bytes, read_32_bytes: bool)

    Read bytes from the device.

    This command can read bytes from an address of one of the memory zones

    See datasheet page 10 for zones details.

    :param zone: Select the source zone. Must be one of `Config`, `OTP` or `Data`.
    :type zone: str
    :param address: 2 bytes address of the first word to be read.
            See datasheet page 58 for correct formats.
    :type address: bytes
    :param read_32_bytes: If True, 32 bytes are read and returned. Otherwise
            4 bytes are read and returned.
    :type read_32_bytes: bool

    :returns: A single word (4 bytes) or a 8-words block (32 bytes), depending on
            the `read_32_bytes` parameter.

            The bytes can be encrypted depending on the zone and the device status.

            See datasheet page 81 for usage details.
    :rtype: bytes
.. method:: sha_start_cmd(self)

    Start a SHA-256 digest computation.
    This command must be run before sha_end_cmd().

    :returns: Single byte 0 if the operation completed correctly.
    :rtype: bytes
..  method:: sha_hmacstart_cmd(self, key_id: bytes)

    Start a HMAC digest computation.

    This command must be run before :meth:`.sha_hmacend_cmd()`.

    :param key_id: Id of the HMAC key.
    :type key_id: bytes

    :returns: Single byte 0 if the operation completed correctly.
    :rtype: bytes
..  method:: sha_update_cmd(self, message: bytes)

    Add 64 bytes in the message parameter to the SHA context.

    This command must be run after :meth:`.sha_start_cmd()` or                :meth:`.sha_hmacstart_cmd()`.

    :param message: 64 bytes, to be added in the SHA context.
    :type message: bytes

    :returns: Single byte 0 if the operation completed correctly.
    :rtype: bytes
..  method:: sha_public_cmd(self, key_id: bytes)

    Add 64 bytes of a public key stored in one of the Data zone slots to the SHA context.

    :param key_id: The slot id of the public key.
    :type key_id: bytes

    :returns: Single byte 0 if the operation completed successfully, or an error if the slot
        contains anything other than a public key.
    :rtype: bytes
..  method:: sha_end_cmd(message: bytes)

    Complete the SHA-256 computation and load the digest into TempKey and the output buffer.

    Up to 63 message bytes are accepted (Length must be 0 through 63 inclusive.)

    This command must be run after `sha_start_cmd()` and eventually after some
    `sha_update_cmd()`.

    :param message: 0-63 bytes to be added in the SHA context before the final computation.
    :type message: bytes

    :returns: 32 bytes representing the SHA256 digest.
    :rtype: bytes
..  method:: sha_hmacend_cmd(message: bytes)

    Complete the HMAC computation and load the digest into TempKey and the output buffer.
    Up to 63 message bytes are accepted (length must be 0 through 63 inclusive).

    This command must be run after `sha_hmacstart_cmd()` and eventually after some
    `sha_update_cmd()`.

    :param message: 0-63 bytes to be added in the SHA context before the final computation.
    :type message: bytes

    :returns: 32 bytes representing the SHA256 digest.
    :rtype: bytes
..  method:: sign_cmd(key_id: bytes, include_sn: bool, use_tempkey: bool,                is_verify_invalidate: bool = False)

    ECDSA signature calculation from an internal private key.

    :param key_id: Internal private key used to generate the signature.
    :type key_id: bytes
    :param include_sn: If True, 48 bits from Configuration Zone are included in the
        digest message.
    :type include_sn: bool
    :param use_tempkey: If True, the message to be signed is in TempKey.
        Otherwise the message is internally generated (see datasheet page 86).
    :type use_tempkey: bool
    :param is_verify_invalidate: This flag must be set to True if the command is
            being used by `verify(invalidate)` (Default value = False).
    :type is_verify_invalidate: bool

    :returns: 64 bytes representing the signature composed of R and S, or an error code.
    :rtype: bytes
..  method:: updateextra_cmd(update_byte: int, new_value: int)

    Update bytes 84 or 85 within the Configuration zone after the Configuration zone
    has been locked.

    :param update_byte: Select the byte to be updated, can be one of 84 or 85.
    :type update_byte: int
    :param new_value: New value to be written in the selected byte.
    :type new_value: int
    :param update_byte: int:
    :param new_value: int:

    :returns: 0 if the operation succeded, or an error status code.
    :rtype: bytes
..  method:: updateextra_decr_cmd(key_id)

    Decrement the limited use counter associated with the key in slot after the
    Configuration zone has been locked.

    If the slot indicated by the “NewValue” param does not contain a key for which limited
    use is implemented or enabled, then the command returns without taking any action.

    If the indicated slot contains a limited use key, which does not have any uses
    remaining, then the command returns an error.

    :param key_id: 2 bytes, the slot id of the key to be decremented.
    :type key_id: bytes

    :returns: 0 if the operation succeded, or an error status code.
    :rtype: bytes
..  method:: verify_external_cmd(curve_type: int, r_comp: bytes, s_comp: bytes,                x_comp: bytes, y_comp: bytes)

    Takes an ECDSA <R,S> signature and verifies that it is correctly generated from a given
    message and public key.
    In this mode the public key is an external input.
    Prior to this command being run, the message should be written to TempKey using the
    Nonce command.

    :param curve_type: Curve type to be used to verify the signature:

            - 0b100 = P256 NIST ECC key

            - 0b111 = Not an ECC key

            The value in this field is encoded identically to the KeyType field in the
            KeyConfig words within the Configuration zone.
    :type curve_type: int
    :param r_comp: 32 bytes, the R component of the ECDSA signature to be verified.
    :type r_comp: bytes
    :param s_comp: 32 bytes, the S component of the ECDSA signature to be verified.
    :type s_comp: bytes
    :param x_comp: 32 bytes, the X component of the public key to be used.
    :type x_comp: bytes
    :param y_comp: 32 bytes, the X component of the public key to be used.
    :type y_comp: bytes

    :returns: 0 if the signature match. 1 if the signature doesn't match.
        An error status code if an error occured.
    :rtype: bytes
..  method:: verify_stored_cmd(key_id: bytes, r_comp: bytes, s_comp: bytes)

    Takes an ECDSA <R,S> signature and verifies that it is correctly generated from a given
    message and public key.

    In this mode the public key to be used is found in the KeyID EEPROM slot.

    The contents of TempKey should contain the SHA-256 digest of the message.

    :param key_id: 2 bytes, the slot id containing the public key to be used.
        The key type is determined by KeyConfig.KeyType.
    :type key_id: bytes
    :param r_comp: 32 bytes, the R component of the ECDSA signature to be verified.
    :type r_comp: bytes
    :param s_comp: 32 bytes, the S component of the ECDSA signature to be verified.
    :type s_comp: bytes

    :returns: 0 if the signature match. 1 if the signature doesn't match. An error status
        code if something went wrong.
    :rtype: bytes
..  method:: verify_validate_cmd(key_id: bytes, r_comp: bytes, s_comp: bytes,                other_data: bytes, invalidate: bool = False)

    The Validate and Invalidate modes are used to validate or invalidate the public key
    stored in the EEPROM.
    The contents of TempKey should contain a digest of the PublicKey at `key_id`.
    It must have been generated using `genkey_cmd` over the `key_id` slot.

    :param key_id: Slot id of the key to be (in)validated.
        The parent key to be used to perform the (in)validation is stored in
        SlotConfig.ReadKey.SlotConfig<ParentKey>.KeyType determines the curve to be used.
    :type key_id: bytes
    :param r_comp: 32 bytes, the R component of the ECDSA signature to be verified.
    :type r_comp: bytes
    :param s_comp: 32 bytes, the S component of the ECDSA signature to be verified.
    :type s_comp: bytes
    :param other_data: 19 bytes, the bytes used to generate the message for the
            validation.
    :type other_data: bytes
    :param invalidate: If True set the mode to Invalidate instead of Validate.
        (Default value = False)
    :type invalidate: bool

    :returns: 0 if the signature match. 1 if the signature doesn't match. An error status
        code if something went wrong.
    :rtype: bytes
..  method:: verify_invalidate_cmd(key_id: bytes, r_comp: bytes, s_comp: bytes,                other_data: bytes)

    Shortcut for :meth:`.verify_validate_cmd()` using `invalidate` mode.
..  method:: verify_validate_external_cmd(key_id: bytes, r_comp: bytes, s_comp: bytes)

    The ValidateExternal mode is used to validate the public key stored in the EEPROM at
    `key_id` when X.509 format certificates are to be used. The digest of the message must
    be TempKey. TempKey must have been generated using the `sha_public_cmd()`, and the
    key for that computation must be the same as `key_id`.

    :param key_id: The slot containing the public key to be validated which must have
            been specified by a previous `sha_public_cmd()`.
    :type key_id: bytes
    :param r_comp: 32 bytes, the R component of the ECDSA signature to be verified.
    :type r_comp: bytes
    :param s_comp: 32 bytes, the S component of the ECDSA signature to be verified.
    :type s_comp: bytes

    :returns: 0 if the signature match. 1 if the signature doesn't match. An error status
        code if something went wrong.
    :rtype: bytes
..  method:: write_cmd(zone: str, address: bytes, value: bytes, is_input_encrypted: bool,                mac: bytes = bytes())

    Writes either one four byte word or an 8-word block of 32 bytes to one of the EEPROM
    zones on the device. Depending upon the value of the WriteConfig byte for this slot,
    the data may be required to be encrypted by the system prior to being sent to the
    device.

    :param zone: Select the source zone. Must be one of `Config`, `OTP` or `Data`.
    :type zone: str
    :param address: 2 bytes address of the first word to be written.
            See datasheet page 58 for correct formats.
    :type address: bytes
    :param value: 4 or 32 bytes to be written in the specified address.
            May be encrypted (set `is_input_encrypted` to True).
    :type value: bytes
    :param is_input_encrypted: Must be set to True if the input is encrypted.
            See datasheet page 91 for details.
    :type is_input_encrypted: bool
    :param mac: Message authentication code to validate address and data.
        (Default value = bytes())
    :type mac: bytes
..  method:: is_locked(zone: str)

    Check if selected zone has been locked.

    :param zone: Select the zone to check. Must be one of `Config` or `Data`.
    :type zone: str

    :returns: True if selected zone is locked.
    :rtype: bool
..  method:: serial_number()

    Retrieve secure element's 72-bit serial number.

    :returns: Serial number.
    :rtype: bytes
=============
ATECC608A class
=============

..  class:: ATECC608A(i2c.I2C)

    Class for controlling the ATECC608A chip.

    This class inherits all ATECC508A methods.
    
==========================
Zerynth HWCrypto Interface
==========================

.. _lib.microchip.ateccx08a.hwcryptointerface

..  function:: hwcrypto_init(i2c_drv, key_slot, i2c_addr=0x60, dev_type=DEV_ATECC508A)

    .. note:: this function is available only when ``ZERYNTH_HWCRYPTO_ATECCx08A`` is set in project.yml file

    :param i2c_drv: Interface for I2C communication. (e.g. ``I2C0``)
    :param key_slot: Chosen private key slot number (can be used to sign, compute public, ...)
    :param i2c_addr: Address of the I2C chip. (Default value = ``0x60``)
    :param dev_type: Crypto chip type (Default = ``DEV_ATECC508A``, can also be ``DEV_ATECC108A`` or ``DEV_ATECC608A``)

    Init and enable the use of the crypto chip from other Zerynth libraries through Zerynth HWCrypto C interface.
    C interface based on `Microchip Cryptoauth Lib <https://github.com/MicrochipTech/cryptoauthlib>`_.


.. node:: ``ATECCx08A_EXCLUDE_PYTHON`` define is available to exclude python code from the compilation process if only the C interface is needed.
    
