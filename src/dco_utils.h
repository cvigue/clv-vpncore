// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_UTILS_H
#define CLV_VPN_DCO_UTILS_H

/**
 * @file dco_utils.h
 * @brief Shared DCO (Data Channel Offload) utility functions.
 *
 * Free functions used by both VpnClient and VpnServer for DCO support.
 * These are Linux-specific and require the ovpn-dco-v2 kernel module.
 */

#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

namespace clv::vpn::dco {

/**
 * @brief Check if DCO is available on this system.
 * @details First checks /proc/modules for a loaded ovpn_dco_v2 module.
 *          If not found, attempts to load it via modprobe (requires
 *          root or CAP_SYS_MODULE). Uses fork+execv to avoid shell
 *          injection risk.
 * @return true if ovpn-dco-v2 kernel module is loaded or was successfully loaded
 */
inline bool IsAvailable()
{
    // Check if ovpn-dco-v2 kernel module is loaded
    std::ifstream modules("/proc/modules");
    if (modules.is_open())
    {
        std::string line;
        while (std::getline(modules, line))
        {
            // Module name is first field (space-separated)
            if (line.find("ovpn_dco_v2") == 0)
                return true;
        }
    }

    // Module not loaded — try to load it (requires root/CAP_SYS_MODULE).
    // Use fork+execv instead of std::system to avoid shell injection risk.
    pid_t pid = fork();
    if (pid == 0)
    {
        // Child: exec modprobe directly, no shell
        const char *argv[] = {"/sbin/modprobe", "ovpn-dco-v2", nullptr};
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
        {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv("/sbin/modprobe", const_cast<char *const *>(argv));
        _exit(127); // exec failed
    }
    else if (pid > 0)
    {
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            return true;
    }

    return false;
}

} // namespace clv::vpn::dco

#endif // CLV_VPN_DCO_UTILS_H
