/**
 *  Copyright (C) 2015 Topology LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef BONEFISH_MESSAGES_WAMP_AUTH_MESSAGE_HPP
#define BONEFISH_MESSAGES_WAMP_AUTH_MESSAGE_HPP

#include <bonefish/identifiers/wamp_session_id.hpp>
#include <bonefish/messages/wamp_message.hpp>
#include <bonefish/messages/wamp_message_defaults.hpp>
#include <bonefish/messages/wamp_message_type.hpp>

#include <cassert>
#include <cstddef>
#include <msgpack.hpp>
#include <ostream>
#include <stdexcept>
#include <vector>

namespace bonefish {

//
// [auth, Session|id, Details|dict]
//
class wamp_auth_message : public wamp_message
{
public:
    wamp_auth_message();
    wamp_auth_message(msgpack::zone&& zone);
    virtual ~wamp_auth_message() override;

    virtual wamp_message_type get_type() const override;
    virtual std::vector<msgpack::object> marshal() const override;
    virtual void unmarshal(
            const std::vector<msgpack::object>& fields,
            msgpack::zone&& zone) override;

    std::string get_response() const;

private:
    msgpack::object m_type;
    msgpack::object m_response;

private:
    static const size_t NUM_FIELDS = 3;
};

inline wamp_auth_message::wamp_auth_message()
    : wamp_auth_message(msgpack::zone())
{
}

inline wamp_auth_message::wamp_auth_message(msgpack::zone&& zone)
    : wamp_message(std::move(zone))
    , m_type(wamp_message_type::AUTHENTICATE)
    , m_response()
{
}

inline wamp_auth_message::~wamp_auth_message()
{
}

inline wamp_message_type wamp_auth_message::get_type() const
{
    return m_type.as<wamp_message_type>();
}

inline std::vector<msgpack::object> wamp_auth_message::marshal() const
{
    std::vector<msgpack::object> fields { m_type, m_response };
    return fields;
}

inline void wamp_auth_message::unmarshal(
        const std::vector<msgpack::object>& fields,
        msgpack::zone&& zone)
{
    if (fields.size() != NUM_FIELDS) {
        throw std::invalid_argument("invalid number of fields");
    }

    if (fields[0].as<wamp_message_type>() != get_type()) {
        throw std::invalid_argument("invalid message type");
    }

    acquire_zone(std::move(zone));
    m_response = fields[1];
}

inline std::string wamp_auth_message::get_response() const 
{
    return m_response.as<std::string>();
}

inline std::ostream& operator<<(std::ostream& os, const wamp_auth_message& message)
{
    os << "auth [" << message.get_response() << "]";
    return os;
}



} // namespace bonefish

#endif // BONEFISH_MESSAGES_WAMP_AUTH_MESSAGE_HPP
