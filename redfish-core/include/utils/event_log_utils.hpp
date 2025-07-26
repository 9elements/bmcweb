// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once

#include "bmcweb_config.h"

#include "app.hpp"
#include "async_resp.hpp"
#include "dbus_utility.hpp"
#include "error_messages.hpp"
#include "generated/enums/log_service.hpp"
#include "http_request.hpp"
#include "http_response.hpp"
#include "http_utility.hpp"
#include "logging.hpp"
#include "query.hpp"
#include "registries.hpp"
#include "registries/privilege_registry.hpp"
#include "str_utility.hpp"
#include "utils/dbus_event_log_entry.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"
#include "utils/log_services_utils.hpp"
#include "utils/query_param.hpp"
#include "utils/time_utils.hpp"

#include <asm-generic/errno.h>
#include <systemd/sd-bus.h>
#include <tinyxml2.h>
#include <unistd.h>

#include <boost/beast/http/field.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/system/linux_error.hpp>
#include <boost/url/format.hpp>
#include <boost/url/url.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/unpack_properties.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace redfish
{
namespace event_log_utils
{

enum class LogParseError
{
    success,
    parseFailed,
    messageIdNotInRegistry,
};

bool getRedfishLogFiles(std::vector<std::filesystem::path>& redfishLogFiles);

bool getUniqueEntryID(const std::string& logEntry, std::string& entryID,
                      bool firstEntry);

std::optional<bool> getProviderNotifyAction(const std::string& notify);

std::string translateSeverityDbusToRedfish(const std::string& s);

void fillEventLogLogEntryFromDbusLogEntry(const DbusEventLogEntry& entry,
                                          nlohmann::json& objectToFillOut);

LogParseError fillEventLogEntryJson(const std::string& logEntryID,
                                    const std::string& logEntry,
                                    nlohmann::json::object_t& logEntryJson);

void afterDBusEventLogEntryGet(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID, const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& resp);

void dBusEventLogEntryGet(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          std::string entryID);

void dBusEventLogEntryPatch(const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& entryId);

void dBusEventLogEntryDelete(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string entryID);

void downloadEventLogEntry(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& resourceID,
                           const std::string& entryID,
                           const std::string& dumpType);

void dBusLogServiceActionsClear(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp);

void handleDBusEventLogEntryDownloadGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resourceID, const std::string& entryID);

void handleLogServicesEventLogActionsClearPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resourceID);

template <typename CallbackFunc>
void handleLogServiceEventLogLogEntryCollection(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resourceID, CallbackFunc&& callback);
} // namespace event_log_utils
} // namespace redfish
