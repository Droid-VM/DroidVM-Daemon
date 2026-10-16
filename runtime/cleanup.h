// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <exception>

namespace droidvm {
// Shutdown must attempt every independent resource release, even when a
// previous step or its diagnostic sink fails. Keep the first failure sticky.
class Cleanup {
public:
    template<class Work, class Report>
    bool attempt(const char* name, Work work, Report report) noexcept {
        try { work(); return true; }
        catch (const std::exception& error) {
            failed_ = true;
            try { report(name, error.what()); } catch (...) {}
        } catch (...) {
            failed_ = true;
            try { report(name, "unknown exception"); } catch (...) {}
        }
        return false;
    }
    bool failed() const noexcept { return failed_; }
private:
    bool failed_ = false;
};
}
