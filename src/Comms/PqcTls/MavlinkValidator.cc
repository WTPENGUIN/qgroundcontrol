/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "MavlinkValidator.h"
#include "QGCLoggingCategory.h"
#include <cstring>

extern "C" {
#include "mavlink.h"
}

QGC_LOGGING_CATEGORY(PQCMavlinkValidatorLog, "qgc.etri.validator")

// ========== Constructor / Destructor ==========

MavlinkValidator::MavlinkValidator(uint8_t channelId)
    : m_channelId(channelId)
    , m_status(nullptr)
    , m_message(nullptr)
{
    // Get channel state from MAVLink library
    m_status = mavlink_get_channel_status(m_channelId);
    m_message = mavlink_get_channel_buffer(m_channelId);

    if (!m_status || !m_message) {
        qCCritical(PQCMavlinkValidatorLog)
            << "[Constructor] Failed to get MAVLink buffers for channel" << m_channelId;
        return;
    }

    // Initialize channel to IDLE state
    mavlink_reset_channel_status(m_channelId);

    qCDebug(PQCMavlinkValidatorLog)
        << "[Constructor] MavlinkValidator initialized for channel" << m_channelId;
}

MavlinkValidator::~MavlinkValidator()
{
    qCDebug(PQCMavlinkValidatorLog)
        << "[Destructor] MavlinkValidator destroyed for channel" << m_channelId;
}

// ========== Public Methods ==========

bool MavlinkValidator::validateAndExtractMavlink(
    const QByteArray& decryptedData,
    mavlink_message_t& outMessage)
{
    if (!m_status || !m_message) {
        qCCritical(PQCMavlinkValidatorLog)
            << "[validateAndExtractMavlink] Invalid state: buffers not initialized";
        return false;
    }

    // ========== Byte-by-byte parsing loop (NO explicit buffering!) ==========
    for (const uint8_t &byte: decryptedData) {
        
        // Parse single byte through MAVLink state machine
        uint8_t result = mavlink_parse_char(
            m_channelId,
            byte,
            &outMessage,
            m_status
        );

        // Check if complete valid packet found
        if (result == MAVLINK_FRAMING_OK) {
            // ✅ Complete valid packet extracted!
            qCDebug(PQCMavlinkValidatorLog)
                << "[validateAndExtractMavlink] ✅ Valid packet"
                << "MsgID:" << outMessage.msgid
                << "Seq:" << outMessage.seq
                << "SysID:" << outMessage.sysid
                << "CompID:" << outMessage.compid;

            // Copy message to output
            std::memcpy(&outMessage, m_message, sizeof(mavlink_message_t));
            return true;
        }

        // result == MAVLINK_FRAMING_INCOMPLETE or error
        // mavlink_parse_char automatically handles:
        // - Bad CRC → state reset to IDLE
        // - Bad Signature → state reset to IDLE
        // - Fragmentation → state preserved for next byte
        // Continue to next byte in loop
    }

    // All bytes processed but no complete packet found
    // Parser state preserved in MAVLink library for next call
    qCDebug(PQCMavlinkValidatorLog)
        << "[validateAndExtractMavlink] No complete packet yet"
        << "Parse state:" << (int)m_status->parse_state;

    return false;
}

void MavlinkValidator::resetChannel()
{
    if (!m_status) {
        qCWarning(PQCMavlinkValidatorLog)
            << "[resetChannel] Status is null, cannot reset";
        return;
    }

    qCDebug(PQCMavlinkValidatorLog)
        << "[resetChannel] Resetting channel" << m_channelId << "to IDLE state";

    mavlink_reset_channel_status(m_channelId);
}
