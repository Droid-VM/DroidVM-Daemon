// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdexcept>
#include <string>
#include <utility>

namespace droidvm {
// Constructed by a trusted adapter after authentication, never from request JSON.
// Principal is a stable identity, not a connection ID or a credential/token.
struct CallContext {
    std::string principal;
    bool authenticated = false;
    bool manage_tasks = false;
    bool administrator = false;
};
enum class ErrorCode {
    invalid_argument, unauthenticated, permission_denied, resource_exhausted,
    unavailable, internal, io_error, task_epoch_mismatch, task_not_found, not_cancellable
};
const char* error_code_name(ErrorCode code);
class ServiceError : public std::runtime_error {
public:
    ServiceError(ErrorCode code, std::string message) : std::runtime_error(std::move(message)), code_(code) {}
    ErrorCode code() const { return code_; }
private:
    ErrorCode code_;
};
}
