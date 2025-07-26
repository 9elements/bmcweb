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
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/event_log_utils.hpp"
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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace redfish
{
using namespace event_log_utils;

inline void handleBMCJournalLogServiceEventLogLogEntryCollection(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId)
{
    query_param::QueryCapabilities capabilities = {
        .canDelegateTop = true,
        .canDelegateSkip = true,
    };
    query_param::Query delegatedQuery;
    if (!redfish::setUpRedfishRouteWithDelegation(app, req, asyncResp,
                                                  delegatedQuery, capabilities))
    {
        return;
    }
    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Managers", managerId);
        return;
    }

    size_t top = delegatedQuery.top.value_or(query_param::Query::maxTop);
    size_t skip = delegatedQuery.skip.value_or(0);

    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        "#LogEntryCollection.LogEntryCollection";
    asyncResp->res.jsonValue["@odata.id"] =
        std::format("/redfish/v1/Managers/{}/LogServices/EventLog/Entries",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "System Event Log Entries";
    asyncResp->res.jsonValue["Description"] =
        "Collection of System Event Log Entries";

    nlohmann::json& logEntryArray = asyncResp->res.jsonValue["Members"];
    logEntryArray = nlohmann::json::array();
    // Go through the log files and create a unique ID for each
    // entry
    std::vector<std::filesystem::path> redfishLogFiles;
    getRedfishLogFiles(redfishLogFiles);
    uint64_t entryCount = 0;
    std::string logEntry;

    // Oldest logs are in the last file, so start there and loop
    // backwards
    for (auto it = redfishLogFiles.rbegin(); it < redfishLogFiles.rend(); it++)
    {
        std::ifstream logStream(*it);
        if (!logStream.is_open())
        {
            continue;
        }

        // Reset the unique ID on the first entry
        bool firstEntry = true;
        while (std::getline(logStream, logEntry))
        {
            std::string idStr;
            if (!getUniqueEntryID(logEntry, idStr, firstEntry))
            {
                continue;
            }
            firstEntry = false;

            nlohmann::json::object_t bmcLogEntry;
            LogParseError status =
                fillEventLogEntryJson(idStr, logEntry, bmcLogEntry);
            if (status == LogParseError::messageIdNotInRegistry)
            {
                continue;
            }
            if (status != LogParseError::success)
            {
                messages::internalError(asyncResp->res);
                return;
            }

            entryCount++;
            // Handle paging using skip (number of entries to skip from the
            // start) and top (number of entries to display)
            if (entryCount <= skip || entryCount > skip + top)
            {
                continue;
            }

            logEntryArray.emplace_back(std::move(bmcLogEntry));
        }
    }
    asyncResp->res.jsonValue["Members@odata.count"] = entryCount;
    if (skip + top < entryCount)
    {
        asyncResp->res.jsonValue["Members@odata.nextLink"] =
            boost::urls::format(
                "/redfish/v1/Managers/{}/LogServices/EventLog/Entries?$skip={}",
                BMCWEB_REDFISH_MANAGER_URI_NAME, std::to_string(skip + top));
    }
}

inline void dBusBMCEventLogEntryCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    // Collections don't include the static data added by SubRoute
    // because it has a duplicate entry for members
    asyncResp->res.jsonValue["@odata.type"] =
        "#LogEntryCollection.LogEntryCollection";
    asyncResp->res.jsonValue["@odata.id"] =
        std::format("/redfish/v1/Managers/{}/LogServices/EventLog/Entries",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
    asyncResp->res.jsonValue["Name"] = "System Event Log Entries";
    asyncResp->res.jsonValue["Description"] =
        "Collection of System Event Log Entries";

    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    sdbusplus::message::object_path path("/xyz/openbmc_project/logging");
    dbus::utility::getManagedObjects(
        "xyz.openbmc_project.Logging", path,
        [asyncResp](const boost::system::error_code& ec,
                    const dbus::utility::ManagedObjectType& resp) {
            afterLogEntriesGetManagedObjects(asyncResp, ec, resp);
        });
}

inline void handleBMCJournalLogServiceEventLogEntriesGet(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& managerId, const std::string& param)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "Managers", managerId);
        return;
    }

    const std::string& targetID = param;

    // Go through the log files and check the unique ID for each
    // entry to find the target entry
    std::vector<std::filesystem::path> redfishLogFiles;
    getRedfishLogFiles(redfishLogFiles);
    std::string logEntry;

    // Oldest logs are in the last file, so start there and loop
    // backwards
    for (auto it = redfishLogFiles.rbegin(); it < redfishLogFiles.rend(); it++)
    {
        std::ifstream logStream(*it);
        if (!logStream.is_open())
        {
            continue;
        }

        // Reset the unique ID on the first entry
        bool firstEntry = true;
        while (std::getline(logStream, logEntry))
        {
            std::string idStr;
            if (!getUniqueEntryID(logEntry, idStr, firstEntry))
            {
                continue;
            }
            firstEntry = false;

            if (idStr == targetID)
            {
                nlohmann::json::object_t bmcLogEntry;
                LogParseError status =
                    fillEventLogEntryJson(idStr, logEntry, bmcLogEntry);
                if (status != LogParseError::success)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                asyncResp->res.jsonValue.update(bmcLogEntry);
                return;
            }
        }
    }
    // Requested ID was not found
    messages::resourceNotFound(asyncResp->res, "LogEntry", targetID);
}

inline void requestRoutesBMCEventLogService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Managers/<str>/LogServices/EventLog/")
        .privileges(redfish::privileges::getLogService)
        .methods(
            boost::beast::http::verb::
                get)([&app](const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& managerId) {
            if (!redfish::setUpRedfishRoute(app, req, asyncResp))
            {
                return;
            }
            if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
            {
                messages::resourceNotFound(asyncResp->res, "Managers",
                                           managerId);
                return;
            }
            asyncResp->res.jsonValue["@odata.id"] =
                std::format("/redfish/v1/Managers/{}/LogServices/EventLog",
                            BMCWEB_REDFISH_MANAGER_URI_NAME);
            asyncResp->res.jsonValue["@odata.type"] =
                "#LogService.v1_2_0.LogService";
            asyncResp->res.jsonValue["Name"] = "System Event Log Service";
            asyncResp->res.jsonValue["Description"] =
                "System Event Log Service";
            asyncResp->res.jsonValue["Id"] = "EventLog";
            asyncResp->res.jsonValue["OverWritePolicy"] =
                log_service::OverWritePolicy::WrapsWhenFull;

            std::pair<std::string, std::string> redfishDateTimeOffset =
                redfish::time_utils::getDateTimeOffsetNow();

            asyncResp->res.jsonValue["DateTime"] = redfishDateTimeOffset.first;
            asyncResp->res.jsonValue["DateTimeLocalOffset"] =
                redfishDateTimeOffset.second;

            asyncResp->res.jsonValue["Entries"]["@odata.id"] = std::format(
                "/redfish/v1/Managers/{}/LogServices/EventLog/Entries",
                BMCWEB_REDFISH_MANAGER_URI_NAME);
            asyncResp->res
                .jsonValue["Actions"]["#LogService.ClearLog"]["target"]

                = std::format(
                    "/redfish/v1/Managers/{}/LogServices/EventLog/Actions/LogService.ClearLog",
                    BMCWEB_REDFISH_MANAGER_URI_NAME);
        });
}

inline void requestRoutesBMCJournalEventLogEntryCollection(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleBMCJournalLogServiceEventLogLogEntryCollection,
            std::ref(app)));
}

inline void requestRoutesBMCDBusEventLogEntryCollection(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Managers",
                                               managerId);
                    return;
                }
                dBusBMCEventLogEntryCollection(asyncResp);
            });
}

inline void requestRoutesBMCJournalEventLogEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleBMCJournalLogServiceEventLogEntriesGet, std::ref(app)));
}

inline void requestRoutesBMCDBusEventLogEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId, const std::string& entryId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Managers",
                                               managerId);
                    return;
                }

                dBusEventLogEntryGet(asyncResp, entryId);
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(redfish::privileges::patchLogEntry)
        .methods(boost::beast::http::verb::patch)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId, const std::string& entryId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Managers",
                                               managerId);
                    return;
                }

                dBusEventLogEntryPatch(req, asyncResp, entryId);
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/<str>/")
        .privileges(
            redfish::privileges::
                deleteLogEntrySubOverComputerSystemLogServiceCollectionLogServiceLogEntryCollection)
        .methods(boost::beast::http::verb::delete_)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId, const std::string& param) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Managers",
                                               managerId);
                    return;
                }
                dBusEventLogEntryDelete(asyncResp, param);
            });
}

inline void requestRoutesBMCDBusEventLogEntryDownload(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/EventLog/Entries/<str>/attachment/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleDBusEventLogEntryDownloadGet, std::ref(app), "System"));
}

inline void requestRoutesBMCJournalEventLogClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/EventLog/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::
                        postLogServiceSubOverComputerSystemLogServiceCollection)
        .methods(boost::beast::http::verb::post)(std::bind_front(
            handleLogServicesEventLogActionsClearPost, std::ref(app)));
}

/**
 * DBusLogServiceActionsClear class supports POST method for ClearLog action.
 */
inline void requestRoutesBMCDBusLogServiceActionsClear(App& app)
{
    /**
     * Function handles POST method request.
     * The Clear Log actions does not require any parameter.The action deletes
     * all entries found in the Entries collection for this Log Service.
     */

    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Managers/<str>/LogServices/EventLog/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::
                        postLogServiceSubOverComputerSystemLogServiceCollection)
        .methods(boost::beast::http::verb::post)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& managerId) {
                if (!redfish::setUpRedfishRoute(app, req, asyncResp))
                {
                    return;
                }
                if (managerId != BMCWEB_REDFISH_MANAGER_URI_NAME)
                {
                    messages::resourceNotFound(asyncResp->res, "Managers",
                                               managerId);
                    return;
                }
                dBusLogServiceActionsClear(asyncResp);
            });
}

} // namespace redfish
