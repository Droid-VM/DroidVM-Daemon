// SPDX-License-Identifier: GPL-3.0-or-later
#include "vm/hugepage.h"
#include <iostream>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace droidvm::vm;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("Hugepage pool contract failed"); }
}

int main() {
    try {
        std::vector<std::pair<int64_t, int64_t>> writes;
        bool write_succeeds = true;
        PoolReservations pool([&](int64_t target, int64_t manual) {
            writes.emplace_back(target, manual);
            return write_succeeds;
        });
        pool.initialize_manual(100);

        {
            auto lease = pool.begin_control();
            require(lease && pool.replace_manual_target(*lease, 4096));
        }
        auto state = pool.snapshot();
        require(state.manual_pages == 4096 && state.pages == 0 && !state.busy);
        require(writes.size() == 1 && writes.back() == std::pair<int64_t, int64_t>{4096, 4096});

        write_succeeds = false;
        {
            auto lease = pool.begin_control();
            require(lease && !pool.replace_manual_target(*lease, 8192));
        }
        state = pool.snapshot();
        require(state.manual_pages == 4096 && state.pages == 0 && !state.busy);

        write_succeeds = true;
        {
            auto lease = pool.begin_control();
            require(lease && pool.admit_manual(*lease, "vm-auto", 7, 1200));
            require(!pool.admit_manual(*lease, "vm-auto", 8, 1200));
        }
        state = pool.snapshot();
        require(state.manual_pages == 4096 && state.pages == 1200 && state.consumers == 1);
        require(writes.size() == 2); // Manual admission reserves acquired pages without another target write.

        {
            auto lease = pool.begin_control();
            require(lease && !pool.replace_manual_target(*lease, 16384));
        }
        pool.release("vm-auto", 6); // Stale generations cannot release the reservation.
        require(pool.snapshot().pages == 1200);
        pool.release("vm-auto", 7);
        state = pool.snapshot();
        require(state.pages == 0 && state.manual_pages == 4096 && writes.size() == 2);

        std::cout << "Hugepage pool contract checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
