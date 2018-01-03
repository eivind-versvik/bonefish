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

#ifndef BONEFISH_MESSAGES_WAMP_AUTH_DETAILS_HPP
#define BONEFISH_MESSAGES_WAMP_AUTH_DETAILS_HPP

#include <msgpack.hpp>
#include <unordered_set>

namespace bonefish {

class wamp_auth_details
{
public:
    wamp_auth_details();
    virtual ~wamp_auth_details();

    inline const int get_iterations() const;
    void set_iterations(int iterations);
    const std::string get_challenge() const;
    inline void set_challenge(std::string challenge);    
    inline const std::string get_salt() const;
    inline void set_salt(std::string salt);
    msgpack::object marshal(msgpack::zone& zone) const;
    void unmarshal(const msgpack::object& details);


private:
    int m_iterations;
    std::string m_salt;
    std::string m_challenge;
};

inline wamp_auth_details::wamp_auth_details()
{
}

inline wamp_auth_details::~wamp_auth_details()
{
}


inline const int wamp_auth_details::get_iterations() const
{
    return m_iterations;
}

inline void wamp_auth_details::set_iterations(int iterations)
{
    m_iterations = iterations;
}


inline const std::string wamp_auth_details::get_challenge() const
{
    return m_challenge;
}

inline void wamp_auth_details::set_challenge(std::string challenge)
{
    m_challenge = challenge;
}


inline const std::string wamp_auth_details::get_salt() const
{
    return m_salt;
}

inline void wamp_auth_details::set_salt(std::string salt)
{
    m_salt = salt;
}

} // namespace bonefish



#endif // BONEFISH_MESSAGES_WAMP_AUTH_DETAILS_HPP
