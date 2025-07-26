// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include "utils/event_log_utils.hpp"

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

namespace redfish
{
namespace event_log_utils
{

std::optional<DbusEventLogEntry> fillDbusEventLogEntryFromPropertyMap(
    const dbus::utility::DBusPropertiesMap& resp)
{
    DbusEventLogEntry entry;

    // clang-format off
    bool success = sdbusplus::unpackPropertiesNoThrow(
        dbus_utils::UnpackErrorPrinter(), resp,
        "Id", entry.Id,
        "Message", entry.Message,
        "Path", entry.Path,
        "Resolution", entry.Resolution,
        "Resolved", entry.Resolved,
        "ServiceProviderNotify", entry.ServiceProviderNotify,
        "Severity", entry.Severity,
        "Timestamp", entry.Timestamp,
        "UpdateTimestamp", entry.UpdateTimestamp
    );
    // clang-format on
    if (!success)
    {
        return std::nullopt;
    }
    return entry;
}

bool getRedfishLogFiles(std::vector<std::filesystem::path>& redfishLogFiles)
{
    static const std::filesystem::path redfishLogDir = "/var/log";
    static const std::string redfishLogFilename = "redfish";

    // Loop through the directory looking for redfish log files
    for (const std::filesystem::directory_entry& dirEnt :
         std::filesystem::directory_iterator(redfishLogDir))
    {
        // If we find a redfish log file, save the path
        std::string filename = dirEnt.path().filename();
        if (filename.starts_with(redfishLogFilename))
        {
            redfishLogFiles.emplace_back(redfishLogDir / filename);
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we don't expect more than 10 log files, we
    // can just sort the list to get them in order from newest to oldest
    std::ranges::sort(redfishLogFiles);

    return !redfishLogFiles.empty();
}

bool getUniqueEntryID(const std::string& logEntry, std::string& entryID,
                      const bool firstEntry = true)
{
    static time_t prevTs = 0;
    static int index = 0;
    if (firstEntry)
    {
        prevTs = 0;
    }

    // Get the entry timestamp
    std::time_t curTs = 0;
    std::tm timeStruct = {};
    std::istringstream entryStream(logEntry);
    if (entryStream >> std::get_time(&timeStruct, "%Y-%m-%dT%H:%M:%S"))
    {
        curTs = std::mktime(&timeStruct);
    }
    // If the timestamp isn't unique, increment the index
    if (curTs == prevTs)
    {
        index++;
    }
    else
    {
        // Otherwise, reset it
        index = 0;
    }
    // Save the timestamp
    prevTs = curTs;

    entryID = std::to_string(curTs);
    if (index > 0)
    {
        entryID += "_" + std::to_string(index);
    }
    return true;
}

std::optional<bool> getProviderNotifyAction(const std::string& notify)
{
    std::optional<bool> notifyAction;
    if (notify == "xyz.openbmc_project.Logging.Entry.Notify.Notify")
    {
        notifyAction = true;
    }
    else if (notify == "xyz.openbmc_project.Logging.Entry.Notify.Inhibit")
    {
        notifyAction = false;
    }

    return notifyAction;
}

std::string translateSeverityDbusToRedfish(const std::string& s)
{
    if ((s == "xyz.openbmc_project.Logging.Entry.Level.Alert") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Critical") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Emergency") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Error"))
    {
        return "Critical";
    }
    if ((s == "xyz.openbmc_project.Logging.Entry.Level.Debug") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Informational") ||
        (s == "xyz.openbmc_project.Logging.Entry.Level.Notice"))
    {
        return "OK";
    }
    if (s == "xyz.openbmc_project.Logging.Entry.Level.Warning")
    {
        return "Warning";
    }
    return "";
}

void afterLogEntriesGetManagedObjects(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const boost::system::error_code& ec,
    const dbus::utility::ManagedObjectType& resp)
{
    if (ec)
    {
        // TODO Handle for specific error code
        BMCWEB_LOG_ERROR("getLogEntriesIfaceData resp_handler got error {}",
                         ec);
        messages::internalError(asyncResp->res);
        return;
    }
    nlohmann::json::array_t entriesArray;
    for (const auto& objectPath : resp)
    {
        dbus::utility::DBusPropertiesMap propsFlattened;
        auto isEntry =
            std::ranges::find_if(objectPath.second, [](const auto& object) {
                return object.first == "xyz.openbmc_project.Logging.Entry";
            });
        if (isEntry == objectPath.second.end())
        {
            continue;
        }

        for (const auto& interfaceMap : objectPath.second)
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                propsFlattened.emplace_back(propertyMap.first,
                                            propertyMap.second);
            }
        }
        std::optional<DbusEventLogEntry> optEntry =
            fillDbusEventLogEntryFromPropertyMap(propsFlattened);

        if (!optEntry.has_value())
        {
            messages::internalError(asyncResp->res);
            return;
        }
        fillEventLogLogEntryFromDbusLogEntry(*optEntry,
                                             entriesArray.emplace_back());
    }

    redfish::json_util::sortJsonArrayByKey(entriesArray, "Id");
    asyncResp->res.jsonValue["Members@odata.count"] = entriesArray.size();
    asyncResp->res.jsonValue["Members"] = std::move(entriesArray);
}

LogParseError fillEventLogEntryJson(const std::string& logEntryID,
                                    const std::string& logEntry,
                                    nlohmann::json::object_t& logEntryJson)
{
    // The redfish log format is "<Timestamp> <MessageId>,<MessageArgs>"
    // First get the Timestamp
    size_t space = logEntry.find_first_of(' ');
    if (space == std::string::npos)
    {
        return LogParseError::parseFailed;
    }
    std::string timestamp = logEntry.substr(0, space);
    // Then get the log contents
    size_t entryStart = logEntry.find_first_not_of(' ', space);
    if (entryStart == std::string::npos)
    {
        return LogParseError::parseFailed;
    }
    std::string_view entry(logEntry);
    entry.remove_prefix(entryStart);
    // Use split to separate the entry into its fields
    std::vector<std::string> logEntryFields;
    bmcweb::split(logEntryFields, entry, ',');
    // We need at least a MessageId to be valid
    auto logEntryIter = logEntryFields.begin();
    if (logEntryIter == logEntryFields.end())
    {
        return LogParseError::parseFailed;
    }
    std::string& messageID = *logEntryIter;
    // Get the Message from the MessageRegistry
    const registries::Message* message = registries::getMessage(messageID);

    logEntryIter++;
    if (message == nullptr)
    {
        BMCWEB_LOG_WARNING("Log entry not found in registry: {}", logEntry);
        return LogParseError::messageIdNotInRegistry;
    }

    std::vector<std::string_view> messageArgs(logEntryIter,
                                              logEntryFields.end());
    messageArgs.resize(message->numberOfArgs);

    std::string msg =
        redfish::registries::fillMessageArgs(messageArgs, message->message);
    if (msg.empty())
    {
        return LogParseError::parseFailed;
    }

    // Get the Created time from the timestamp. The log timestamp is in RFC3339
    // format which matches the Redfish format except for the fractional seconds
    // between the '.' and the '+', so just remove them.
    std::size_t dot = timestamp.find_first_of('.');
    std::size_t plus = timestamp.find_first_of('+');
    if (dot != std::string::npos && plus != std::string::npos)
    {
        timestamp.erase(dot, plus - dot);
    }

    // Fill in the log entry with the gathered data
    logEntryJson["@odata.type"] = "#LogEntry.v1_9_0.LogEntry";
    if constexpr (BMCWEB_REDFISH_BMC_EVENT_LOG)
    {
        logEntryJson["@odata.id"] = boost::urls::format(
            "/redfish/v1/Managers/{}/LogServices/EventLog/Entries/{}",
            BMCWEB_REDFISH_MANAGER_URI_NAME, logEntryID);
        logEntryJson["Name"] = "Event Log Entry";
    }
    else
    {
        logEntryJson["@odata.id"] = boost::urls::format(
            "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}",
            BMCWEB_REDFISH_SYSTEM_URI_NAME, logEntryID);
        logEntryJson["Name"] = "System Event Log Entry";
    }
    logEntryJson["Id"] = logEntryID;
    logEntryJson["Message"] = std::move(msg);
    logEntryJson["MessageId"] = std::move(messageID);
    logEntryJson["MessageArgs"] = messageArgs;
    logEntryJson["EntryType"] = "Event";
    logEntryJson["Severity"] = message->messageSeverity;
    logEntryJson["Created"] = std::move(timestamp);
    return LogParseError::success;
}

void fillEventLogLogEntryFromDbusLogEntry(const DbusEventLogEntry& entry,
                                          nlohmann::json& objectToFillOut)
{
    objectToFillOut["@odata.type"] = "#LogEntry.v1_9_0.LogEntry";
    if constexpr (BMCWEB_REDFISH_BMC_EVENT_LOG)
    {
        objectToFillOut["@odata.id"] = boost::urls::format(
            "/redfish/v1/Managers/{}/LogServices/EventLog/Entries/{}",
            BMCWEB_REDFISH_MANAGER_URI_NAME, std::to_string(entry.Id));
        objectToFillOut["Name"] = "System Event Log Entry";
    }
    else
    {
        objectToFillOut["@odata.id"] = boost::urls::format(
            "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}",
            BMCWEB_REDFISH_SYSTEM_URI_NAME, std::to_string(entry.Id));
        objectToFillOut["Name"] = "System Event Log Entry";
    }
    objectToFillOut["Id"] = std::to_string(entry.Id);
    objectToFillOut["Message"] = entry.Message;
    objectToFillOut["Resolved"] = entry.Resolved;
    std::optional<bool> notifyAction =
        getProviderNotifyAction(entry.ServiceProviderNotify);
    if (notifyAction)
    {
        objectToFillOut["ServiceProviderNotified"] = *notifyAction;
    }
    if ((entry.Resolution != nullptr) && !entry.Resolution->empty())
    {
        objectToFillOut["Resolution"] = *entry.Resolution;
    }
    objectToFillOut["EntryType"] = "Event";
    objectToFillOut["Severity"] =
        translateSeverityDbusToRedfish(entry.Severity);
    objectToFillOut["Created"] =
        redfish::time_utils::getDateTimeUintMs(entry.Timestamp);
    objectToFillOut["Modified"] =
        redfish::time_utils::getDateTimeUintMs(entry.UpdateTimestamp);
    if (entry.Path != nullptr)
    {
        if constexpr (BMCWEB_REDFISH_BMC_EVENT_LOG)
        {
            objectToFillOut["AdditionalDataURI"] = boost::urls::format(
                "/redfish/v1/Managers/{}/LogServices/EventLog/Entries/{}/attachment",
                BMCWEB_REDFISH_MANAGER_URI_NAME, std::to_string(entry.Id));
        }
        else
        {
            objectToFillOut["AdditionalDataURI"] = boost::urls::format(
                "/redfish/v1/Systems/{}/LogServices/EventLog/Entries/{}/attachment",
                BMCWEB_REDFISH_SYSTEM_URI_NAME, std::to_string(entry.Id));
        }
    }
}

void afterDBusEventLogEntryGet(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID, const boost::system::error_code& ec,
    const dbus::utility::DBusPropertiesMap& resp)
{
    if (ec.value() == EBADR)
    {
        messages::resourceNotFound(asyncResp->res, "EventLogEntry", entryID);
        return;
    }
    if (ec)
    {
        BMCWEB_LOG_ERROR("EventLogEntry (DBus) resp_handler got error {}", ec);
        messages::internalError(asyncResp->res);
        return;
    }

    std::optional<DbusEventLogEntry> optEntry =
        fillDbusEventLogEntryFromPropertyMap(resp);

    if (!optEntry.has_value())
    {
        messages::internalError(asyncResp->res);
        return;
    }

    fillEventLogLogEntryFromDbusLogEntry(*optEntry, asyncResp->res.jsonValue);
}

void dBusEventLogEntryGet(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          std::string entryID)
{
    dbus::utility::escapePathForDbus(entryID);

    // DBus implementation of EventLog/Entries
    // Make call to Logging Service to find all log entry objects
    dbus::utility::getAllProperties(
        "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/entry/" + entryID, "",
        std::bind_front(afterDBusEventLogEntryGet, asyncResp, entryID));
}

void dBusEventLogEntryPatch(const crow::Request& req,
                            const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                            const std::string& entryId)
{
    std::optional<bool> resolved;

    if (!json_util::readJsonPatch(req, asyncResp->res, "Resolved", resolved))
    {
        return;
    }
    BMCWEB_LOG_DEBUG("Set Resolved");

    setDbusProperty(asyncResp, "Resolved", "xyz.openbmc_project.Logging",
                    "/xyz/openbmc_project/logging/entry/" + entryId,
                    "xyz.openbmc_project.Logging.Entry", "Resolved",
                    resolved.value_or(false));
}

void dBusEventLogEntryDelete(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp, std::string entryID)
{
    BMCWEB_LOG_DEBUG("Do delete single event entries.");

    dbus::utility::escapePathForDbus(entryID);

    // Process response from Logging service.
    auto respHandler = [asyncResp,
                        entryID](const boost::system::error_code& ec) {
        BMCWEB_LOG_DEBUG("EventLogEntry (DBus) doDelete callback: Done");
        if (ec)
        {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            // TODO Handle for specific error code
            BMCWEB_LOG_ERROR(
                "EventLogEntry (DBus) doDelete respHandler got error {}", ec);
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }

        asyncResp->res.result(boost::beast::http::status::ok);
    };

    // Make call to Logging service to request Delete Log
    dbus::utility::async_method_call(
        asyncResp, respHandler, "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging/entry/" + entryID,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

void downloadEventLogEntry(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                           const std::string& resourceID,
                           const std::string& entryID,
                           const std::string& dumpType)
{
    if constexpr (BMCWEB_REDFISH_BMC_EVENT_LOG)
    {
        if (resourceID != BMCWEB_REDFISH_MANAGER_URI_NAME)
        {
            messages::resourceNotFound(asyncResp->res, "Managers", resourceID);
            return;
        }
    }
    if (resourceID != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   resourceID);
        return;
    }

    std::string entryPath =
        sdbusplus::message::object_path("/xyz/openbmc_project/logging/entry") /
        entryID;

    auto downloadEventLogEntryHandler =
        [asyncResp, entryID,
         dumpType](const boost::system::error_code& ec,
                   const sdbusplus::message::unix_fd& unixfd) {
            log_services_utils::downloadEntryCallback(asyncResp, entryID,
                                                      dumpType, ec, unixfd);
        };

    dbus::utility::async_method_call(
        asyncResp, std::move(downloadEventLogEntryHandler),
        "xyz.openbmc_project.Logging", entryPath,
        "xyz.openbmc_project.Logging.Entry", "GetEntry");
}

void dBusLogServiceActionsClear(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    BMCWEB_LOG_DEBUG("Do delete all entries.");

    // Process response from Logging service.
    auto respHandler = [asyncResp](const boost::system::error_code& ec) {
        BMCWEB_LOG_DEBUG("doClearLog resp_handler callback: Done");
        if (ec)
        {
            // TODO Handle for specific error code
            BMCWEB_LOG_ERROR("doClearLog resp_handler got error {}", ec);
            asyncResp->res.result(
                boost::beast::http::status::internal_server_error);
            return;
        }

        messages::success(asyncResp->res);
    };

    // Make call to Logging service to request Clear Log
    dbus::utility::async_method_call(
        asyncResp, respHandler, "xyz.openbmc_project.Logging",
        "/xyz/openbmc_project/logging",
        "xyz.openbmc_project.Collection.DeleteAll", "DeleteAll");
}

void handleDBusEventLogEntryDownloadGet(
    crow::App& app, const std::string& dumpType, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resourceID, const std::string& entryID)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    if (!http_helpers::isContentTypeAllowed(
            req.getHeaderValue("Accept"),
            http_helpers::ContentType::OctetStream, true))
    {
        asyncResp->res.result(boost::beast::http::status::bad_request);
        return;
    }
    downloadEventLogEntry(asyncResp, resourceID, entryID, dumpType);
}

void handleLogServicesEventLogActionsClearPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& resourceID)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }

    if (resourceID != BMCWEB_REDFISH_SYSTEM_URI_NAME)
    {
        messages::resourceNotFound(asyncResp->res, "ComputerSystem",
                                   resourceID);
        return;
    }

    // Clear the EventLog by deleting the log files
    std::vector<std::filesystem::path> redfishLogFiles;
    if (getRedfishLogFiles(redfishLogFiles))
    {
        for (const std::filesystem::path& file : redfishLogFiles)
        {
            std::error_code ec;
            std::filesystem::remove(file, ec);
        }
    }

    // Reload rsyslog so it knows to start new log files
    dbus::utility::async_method_call(
        asyncResp,
        [asyncResp](const boost::system::error_code& ec) {
            if (ec)
            {
                BMCWEB_LOG_ERROR("Failed to reload rsyslog: {}", ec);
                messages::internalError(asyncResp->res);
                return;
            }

            messages::success(asyncResp->res);
        },
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "ReloadUnit", "rsyslog.service",
        "replace");
}

} // namespace event_log_utils
} // namespace redfish
