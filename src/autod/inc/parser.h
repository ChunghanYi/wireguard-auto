/*
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "message.h"

namespace parser
{
	void parse_Go_message_string(const char* rbuf, message_t* rmsg);
}
