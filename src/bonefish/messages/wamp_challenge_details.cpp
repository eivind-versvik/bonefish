#include <msgpack/object.hpp>
#include <msgpack/pack.hpp>
#include <bonefish/messages/wamp_challenge_details.hpp>


namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {

object const& operator>> (msgpack::object const&, bonefish::wamp_challenge_details&)
{
    throw std::logic_error("no msgpack object deserializer defined");
}

template <typename Stream>
packer<Stream>& operator<< (packer<Stream>&, bonefish::wamp_challenge_details const&)
{
    throw std::logic_error("no msgpack object packer serializer defined");
}

template<>
void operator<< (object::with_zone& details,
        bonefish::wamp_challenge_details const& challenge_details)
{
    details.type = type::MAP;
    details.via.map.size = 4;
    details.via.map.ptr = static_cast<object_kv*>(
            details.zone.allocate_align(sizeof(object_kv) * details.via.map.size));
    details.via.map.ptr[0].key = object(std::string("salt"), details.zone);
    details.via.map.ptr[0].val = object(challenge_details.get_salt(), details.zone);
    details.via.map.ptr[1].key = object(std::string("challenge"), details.zone);
    details.via.map.ptr[1].val = object(challenge_details.get_challenge(), details.zone);
    details.via.map.ptr[2].key = object(std::string("iterations"), details.zone);
    details.via.map.ptr[2].val = object(challenge_details.get_iterations(), details.zone);
    details.via.map.ptr[3].key = object(std::string("keylen"), details.zone);
    details.via.map.ptr[3].val = object(32, details.zone);

    
}

} // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
} // namespace msgpack

namespace bonefish {


msgpack::object wamp_challenge_details::marshal(msgpack::zone& zone) const
{
    return msgpack::object(*this, zone);
}

void wamp_challenge_details::unmarshal(const msgpack::object& object)
{
    throw std::logic_error("unmarshal not implemented");
}

}