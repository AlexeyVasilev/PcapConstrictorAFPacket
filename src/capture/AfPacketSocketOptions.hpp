#pragma once

#include <string>
#include <string_view>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <sstream>

#include <linux/if_packet.h>
#include <sys/socket.h>
#endif

namespace pcap_constrictor_afpacket {

#if defined(__linux__)
inline bool EnablePromiscuousMembership(const int socket_fd,
                                        const unsigned int ifindex,
                                        const std::string_view interface_name,
                                        std::string& error_message) {
    packet_mreq request{};
    request.mr_ifindex = static_cast<int>(ifindex);
    request.mr_type = PACKET_MR_PROMISC;

    if (::setsockopt(socket_fd,
                     SOL_PACKET,
                     PACKET_ADD_MEMBERSHIP,
                     &request,
                     sizeof(request)) == 0) {
        return true;
    }

    std::ostringstream out;
    out << "failed to enable promiscuous mode on interface '" << interface_name
        << "': " << std::strerror(errno);
    error_message = out.str();
    return false;
}

inline void DisablePromiscuousMembership(const int socket_fd,
                                         const unsigned int ifindex) noexcept {
    if (socket_fd < 0 || ifindex == 0U) {
        return;
    }

    packet_mreq request{};
    request.mr_ifindex = static_cast<int>(ifindex);
    request.mr_type = PACKET_MR_PROMISC;
    (void)::setsockopt(socket_fd,
                       SOL_PACKET,
                       PACKET_DROP_MEMBERSHIP,
                       &request,
                       sizeof(request));
}
#endif

}  // namespace pcap_constrictor_afpacket
