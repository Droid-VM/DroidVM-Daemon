// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "usb_acm.h"
#include <sys/types.h>
namespace droidvm { UsbAcmOptions usb_acm_store(int directory, uid_t owner, vm::AcmControl& pool); }
