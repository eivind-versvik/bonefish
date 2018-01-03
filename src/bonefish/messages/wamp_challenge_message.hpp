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

#ifndef BONEFISH_MESSAGES_WAMP_CHALLENGE_MESSAGE_HPP
#define BONEFISH_MESSAGES_WAMP_CHALLENGE_MESSAGE_HPP

#include <bonefish/messages/wamp_message.hpp>
#include <bonefish/messages/wamp_message_defaults.hpp>
#include <bonefish/messages/wamp_message_type.hpp>
#include <bonefish/messages/wamp_challenge_details.hpp>

#include <cassert>
#include <cstddef>
#include <msgpack.hpp>
#include <ostream>
#include <stdexcept>
#include <vector>

namespace bonefish {

//
// [challenge, method, Details|dict]
//
class wamp_challenge_message : public wamp_message
{
public:
    wamp_challenge_message();
    wamp_challenge_message(msgpack::zone&& zone);
    virtual ~wamp_challenge_message() override;

    virtual wamp_message_type get_type() const override;
    virtual std::vector<msgpack::object> marshal() const override;
    virtual void unmarshal(
            const std::vector<msgpack::object>& fields,
            msgpack::zone&& zone) override;

    std::string get_method() const;
    const msgpack::object& get_authDetails() const;

    void set_method(const std::string& method);
    void set_authDetails(const msgpack::object&);

private:
    msgpack::object m_type;
    msgpack::object m_method;
    msgpack::object m_authDetails;

private:
    static const size_t NUM_FIELDS = 3;
};

inline wamp_challenge_message::wamp_challenge_message()
    : wamp_challenge_message(msgpack::zone())
{
}

inline wamp_challenge_message::wamp_challenge_message(msgpack::zone&& zone)
    : wamp_message(std::move(zone))
    , m_type(wamp_message_type::CHALLENGE)
    , m_method()
    , m_authDetails(msgpack_empty_map())
{
}

inline wamp_challenge_message::~wamp_challenge_message()
{
}

inline wamp_message_type wamp_challenge_message::get_type() const
{
    return m_type.as<wamp_message_type>();
}

inline std::vector<msgpack::object> wamp_challenge_message::marshal() const
{
    std::vector<msgpack::object> fields { m_type, m_method, m_authDetails };
    return fields;
}

inline void wamp_challenge_message::unmarshal(
        const std::vector<msgpack::object>& fields,
        msgpack::zone&& zone)
{
    throw std::logic_error("unmarshal not implemented");
}

inline std::string wamp_challenge_message::get_method() const
{
    return m_method.as<std::string>();
}

inline const msgpack::object& wamp_challenge_message::get_authDetails() const
{
    return m_authDetails;
}

inline void wamp_challenge_message::set_method(const std::string& method)
{
    m_method =  msgpack::object(method, get_zone());
}

inline void wamp_challenge_message::set_authDetails(const msgpack::object& authDetails)
{
    m_authDetails = msgpack::object(authDetails, get_zone());
}

inline std::ostream& operator<<(std::ostream& os, const wamp_challenge_message& message)
{
    os << "challenge [" << message.get_method() << ", "
            << message.get_authDetails() << "]";
    return os;
}

} // namespace bonefish

#endif // BONEFISH_MESSAGES_WAMP_challenge_MESSAGE_HPP
