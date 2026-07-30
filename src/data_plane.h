// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DATA_PLANE_H
#define CLV_VPN_DATA_PLANE_H

/**
 * @file data_plane.h
 * @brief Handle for one composed transport engine.
 *
 * Thin wrapper over std::variant<monostate, Engines...> that centralizes the
 * "skip empty / visit active engine" pattern previously duplicated in VpnServer
 * and VpnClient.
 */

#include <type_traits>
#include <utility>
#include <variant>

namespace clv::vpn {

/**
 * @tparam Engines  Concrete transport leaves (UDP / DCO / TCP, …).
 */
template <typename... Engines>
class DataPlane
{
  public:
    using Variant = std::variant<std::monostate, Engines...>;

    DataPlane() = default;

    DataPlane(const DataPlane &) = delete;
    DataPlane &operator=(const DataPlane &) = delete;
    DataPlane(DataPlane &&) = delete;
    DataPlane &operator=(DataPlane &&) = delete;

    /**
     * @brief Construct the active transport engine in-place.
     * @tparam T Engine type (one of Engines...)
     * @tparam Args Constructor argument types for @p T
     * @param args Forwarded to @p T's constructor
     * @return Reference to the emplaced engine
     */
    template <typename T, typename... Args>
    T &Emplace(Args &&...args)
    {
        return storage_.template emplace<T>(std::forward<Args>(args)...);
    }

    /** Invoke @p f on the active engine; no-op while empty (monostate). */
    template <typename F>
    void Visit(F &&f)
    {
        VisitImpl(storage_, std::forward<F>(f));
    }

    /** Invoke @p f on the active engine; no-op while empty (monostate). */
    template <typename F>
    void Visit(F &&f) const
    {
        VisitImpl(storage_, std::forward<F>(f));
    }

    /**
     * @brief Whether no transport engine has been emplaced yet.
     * @return true while storage holds monostate
     */
    [[nodiscard]] bool empty() const noexcept
    {
        return std::holds_alternative<std::monostate>(storage_);
    }

  private:
    template <typename VariantT, typename F>
    static void VisitImpl(VariantT &v, F &&f)
    {
        std::visit(
            [&](auto &dp)
        {
            if constexpr (!std::is_same_v<std::decay_t<decltype(dp)>, std::monostate>)
                f(dp);
        },
            v);
    }

    Variant storage_;
};

} // namespace clv::vpn

#endif // CLV_VPN_DATA_PLANE_H
