// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "async_resp.hpp"
#include "http_response.hpp"

#include <sdbusplus/message/native_types.hpp>
namespace redfish
{
namespace log_services_utils
{
bool checkSizeLimit(int fd, crow::Response& res);

void downloadEntryCallback(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& entryID,
                           const std::string& downloadEntryType,
                           const boost::system::error_code& ec,
                           const sdbusplus::message::unix_fd& unixfd);
} // namespace log_services_utils
} // namespace redfish
