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

#ifndef BONEFISH_WAMP_CONNECTION_BASE_HPP
#define BONEFISH_WAMP_CONNECTION_BASE_HPP

#include <bonefish/identifiers/wamp_session_id.hpp>
#include <bonefish/messages/wamp_hello_message.hpp>
#include <string>

namespace bonefish {

class wamp_connection_base
{
public:
    wamp_connection_base();
    virtual ~wamp_connection_base();

    bool has_realm() const;
    void set_realm(const std::string& realm);
    const std::string& get_realm() const;

    bool has_session_id() const;
    void set_session_id(const wamp_session_id& id);
    const wamp_session_id& get_session_id() const;

    const std::string& get_challenge_signature() const;
    void set_challenge_signature(std::string& signature);

    std::shared_ptr<wamp_message> get_pending_hello_message() const;
    void set_pending_hello_message(const std::shared_ptr<wamp_message>& hello_message);

    void clear_data();

private:
    std::string m_realm;
    wamp_session_id m_session_id;
    std::string m_challenge_signature;
    std::shared_ptr<wamp_message> m_pending_hello_message;
};

inline wamp_connection_base::wamp_connection_base()
    : m_realm()
    , m_session_id()
{
}

inline wamp_connection_base::~wamp_connection_base()
{
}

inline bool wamp_connection_base::has_realm() const
{
    return !m_realm.empty();
}

inline std::shared_ptr<wamp_message> wamp_connection_base::get_pending_hello_message() const
{
    return m_pending_hello_message;
}


inline void wamp_connection_base::set_pending_hello_message(const std::shared_ptr<wamp_message>& hello_message)
{
    m_pending_hello_message = hello_message;
}

inline const std::string& wamp_connection_base::get_challenge_signature() const
{
    return m_challenge_signature;
}

inline void wamp_connection_base::set_challenge_signature(std::string& challenge_signature)
{
    m_challenge_signature = challenge_signature;
}


inline void wamp_connection_base::set_realm(const std::string& realm)
{
    m_realm = realm;
}

inline const std::string& wamp_connection_base::get_realm() const
{
    return m_realm;
}

inline bool wamp_connection_base::has_session_id() const
{
    return m_session_id.is_valid();
}

inline void wamp_connection_base::set_session_id(const wamp_session_id& id)
{
    m_session_id = id;
}

inline const wamp_session_id& wamp_connection_base::get_session_id() const
{
    return m_session_id;
}

inline void wamp_connection_base::clear_data()
{
    m_session_id = wamp_session_id();
    m_realm = std::string();
    m_challenge_signature = nullptr;
    m_pending_hello_message = nullptr;
}

} // namespace bonefish

#endif // BONEFISH_WAMP_CONNECTION_BASE_HPP
