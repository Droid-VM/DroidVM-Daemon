// SPDX-License-Identifier: GPL-3.0-or-later
#include "context.h"

namespace droidvm {
const char* error_code_name(ErrorCode code) {
    switch (code) {
        case ErrorCode::invalid_argument: return "INVALID_ARGUMENT";
        case ErrorCode::unauthenticated: return "UNAUTHENTICATED";
        case ErrorCode::permission_denied: return "PERMISSION_DENIED";
        case ErrorCode::resource_exhausted: return "RESOURCE_EXHAUSTED";
        case ErrorCode::unavailable: return "UNAVAILABLE";
        case ErrorCode::internal: return "INTERNAL";
        case ErrorCode::io_error: return "IO_ERROR";
        case ErrorCode::task_epoch_mismatch: return "TASK_EPOCH_MISMATCH";
        case ErrorCode::task_not_found: return "TASK_NOT_FOUND";
        case ErrorCode::not_cancellable: return "NOT_CANCELLABLE";
    }
    return "INTERNAL";
}
}
