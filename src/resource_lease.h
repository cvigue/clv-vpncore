// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_RESOURCE_LEASE_H
#define CLV_VPN_RESOURCE_LEASE_H

#include <optional>
#include <utility>

namespace clv::vpn {

/**
 * @brief Move-only RAII lease over a pool-allocated value.
 *
 * @tparam Pool  Pool type providing `void Release(Value)` (or compatible).
 * @tparam Value Allocated resource type.
 *
 * Destructor returns the value to the pool. Moved-from and default-constructed
 * leases are empty and do not release.
 */
template <typename Pool, typename Value>
class PoolLease
{
  public:
    PoolLease() noexcept = default;

    PoolLease(Pool *pool, Value value) noexcept
        : pool_(pool), value_(std::move(value))
    {
    }

    PoolLease(PoolLease &&other) noexcept
        : pool_(other.pool_), value_(std::move(other.value_))
    {
        other.pool_ = nullptr;
        other.value_.reset();
    }

    PoolLease &operator=(PoolLease &&other) noexcept
    {
        if (this != &other)
        {
            Reset();
            pool_ = other.pool_;
            value_ = std::move(other.value_);
            other.pool_ = nullptr;
            other.value_.reset();
        }
        return *this;
    }

    PoolLease(const PoolLease &) = delete;
    PoolLease &operator=(const PoolLease &) = delete;

    ~PoolLease()
    {
        Reset();
    }

    [[nodiscard]] bool has_value() const noexcept
    {
        return value_.has_value();
    }

    explicit operator bool() const noexcept
    {
        return has_value();
    }

    [[nodiscard]] const Value &value() const
    {
        return *value_;
    }

    [[nodiscard]] Value value_or(Value fallback) const
    {
        return value_.value_or(std::move(fallback));
    }

    /** @brief Return the resource to the pool immediately. */
    void Reset() noexcept
    {
        if (pool_ && value_)
        {
            pool_->Release(*value_);
            value_.reset();
        }
        pool_ = nullptr;
    }

    /**
     * @brief Drop ownership without returning the resource to the pool.
     * @return The held value, if any
     */
    [[nodiscard]] std::optional<Value> ReleaseOwnership() noexcept
    {
        pool_ = nullptr;
        std::optional<Value> out = std::move(value_);
        value_.reset();
        return out;
    }

  private:
    Pool *pool_ = nullptr;
    std::optional<Value> value_;
};

} // namespace clv::vpn

#endif // CLV_VPN_RESOURCE_LEASE_H
