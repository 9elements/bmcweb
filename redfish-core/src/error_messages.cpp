/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#include <error_messages.hpp>
#include <crow/logging.h>

namespace redfish {

namespace messages {

void addMessageToErrorJson(nlohmann::json& target,
                           const nlohmann::json& message) {
  auto& error = target["error"];

  // If this is the first error message, fill in the information from the first
  // error message to the top level struct
  if (!error.is_object()) {
    auto message_id_iterator = message.find("MessageId");
    if (message_id_iterator == message.end()) {
      BMCWEB_LOG_CRITICAL << "Attempt to add error message without MessageId";
      return;
    }

    auto message_field_iterator = message.find("Message");
    if (message_field_iterator == message.end()) {
      BMCWEB_LOG_CRITICAL << "Attempt to add error message without Message";
      return;
    }
    // clang-format off
    error = {
        {"code", *message_id_iterator},
        {"message", *message_field_iterator}
    };
    // clang-format on
  } else {
    // More than 1 error occurred, so the message has to be generic
    error["code"] = std::string(messageVersionPrefix) + "GeneralError";
    error["message"] =
        "A general error has occurred. See ExtendedInfo for more"
        "information.";
  }

  // This check could technically be done in in the default construction
  // branch above, but because we need the pointer to the extended info field
  // anyway, it's more efficient to do it here.
  auto& extended_info = error[messages::messageAnnotation];
  if (!extended_info.is_array()) {
    extended_info = nlohmann::json::array();
  }

  extended_info.push_back(message);
}

void addMessageToJsonRoot(nlohmann::json& target,
                          const nlohmann::json& message) {
  if (!target[messages::messageAnnotation].is_array()) {
    // Force object to be an array
    target[messages::messageAnnotation] = nlohmann::json::array();
  }

  target[messages::messageAnnotation].push_back(message);
}

void addMessageToJson(nlohmann::json& target, const nlohmann::json& message,
                      const std::string& fieldPath) {
  nlohmann::json_pointer<nlohmann::json> extendedInfo(
      fieldPath + messages::messageAnnotation);

  if (!target[extendedInfo].is_array()) {
    // Force object to be an array
    target[extendedInfo] = nlohmann::json::array();
  }

  // Object exists and it is an array so we can just push in the message
  target[extendedInfo].push_back(message);
}

/*********************************
 * AUTOGENERATED FUNCTIONS START *
 *********************************/

/**
 * @internal
 * @brief Formats ResourceInUse message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceInUse() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceInUse"},
      {"Message",
       "The change to the requested resource failed because the resource is in "
       "use or in transition."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the condition and resubmit the request if the operation "
       "failed."}};
}

/**
 * @internal
 * @brief Formats MalformedJSON message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json malformedJSON() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.MalformedJSON"},
      {"Message",
       "The request body submitted was malformed JSON and could not be parsed "
       "by the receiving service."},
      {"Severity", "Critical"},
      {"Resolution",
       "Ensure that the request body is valid JSON and resubmit the request."}};
}

/**
 * @internal
 * @brief Formats ResourceMissingAtURI message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceMissingAtURI(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceMissingAtURI"},
      {"Message", "The resource at the URI " + arg1 + " was not found."},
      {"Severity", "Critical"},
      {"Resolution",
       "Place a valid resource at the URI or correct the URI and resubmit the "
       "request."}};
}

/**
 * @internal
 * @brief Formats ActionParameterValueFormatError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterValueFormatError(const std::string& arg1,
                                               const std::string& arg2,
                                               const std::string& arg3) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterValueFormatError"},
      {"Message",
       "The value " + arg1 + " for the parameter " + arg2 + " in the action " +
           arg3 + " is of a different format than the parameter can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the parameter in the request body and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats InternalError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json internalError() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.InternalError"},
      {"Message",
       "The request failed due to an internal service error.  The service is "
       "still operational."},
      {"Severity", "Critical"},
      {"Resolution",
       "Resubmit the request.  If the problem persists, consider resetting the "
       "service."}};
}

/**
 * @internal
 * @brief Formats UnrecognizedRequestBody message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json unrecognizedRequestBody() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.UnrecognizedRequestBody"},
      {"Message",
       "The service detected a malformed request body that it was unable to "
       "interpret."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the request body and resubmit the request if it failed."}};
}

/**
 * @internal
 * @brief Formats ResourceAtUriUnauthorized message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceAtUriUnauthorized(const std::string& arg1,
                                         const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceAtUriUnauthorized"},
      {"Message", "While accessing the resource at " + arg1 +
                      ", the service received an authorization error " + arg2 +
                      "."},
      {"Severity", "Critical"},
      {"Resolution",
       "Ensure that the appropriate access is provided for the service in "
       "order for it to access the URI."}};
}

/**
 * @internal
 * @brief Formats ActionParameterUnknown message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterUnknown(const std::string& arg1,
                                      const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterUnknown"},
      {"Message", "The action " + arg1 +
                      " was submitted with the invalid parameter " + arg2 +
                      "."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the invalid parameter and resubmit the request if the "
       "operation failed."}};
}

/**
 * @internal
 * @brief Formats ResourceCannotBeDeleted message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceCannotBeDeleted() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceCannotBeDeleted"},
      {"Message",
       "The delete request failed because the resource requested cannot be "
       "deleted."},
      {"Severity", "Critical"},
      {"Resolution", "Do not attempt to delete a non-deletable resource."}};
}

/**
 * @internal
 * @brief Formats PropertyDuplicate message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyDuplicate(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyDuplicate"},
      {"Message", "The property " + arg1 + " was duplicated in the request."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the duplicate property from the request body and resubmit the "
       "request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ServiceTemporarilyUnavailable message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json serviceTemporarilyUnavailable(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ServiceTemporarilyUnavailable"},
      {"Message", "The service is temporarily unavailable.  Retry in " + arg1 +
                      " seconds."},
      {"Severity", "Critical"},
      {"Resolution",
       "Wait for the indicated retry duration and retry the operation."}};
}

/**
 * @internal
 * @brief Formats ResourceAlreadyExists message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceAlreadyExists(const std::string& arg1,
                                     const std::string& arg2,
                                     const std::string& arg3) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceAlreadyExists"},
      {"Message", "The requested resource of type " + arg1 +
                      " with the property " + arg2 + " with the value " + arg3 +
                      " already exists."},
      {"Severity", "Critical"},
      {"Resolution",
       "Do not repeat the create operation as the resource has already been "
       "created."}};
}

/**
 * @internal
 * @brief Formats AccountForSessionNoLongerExists message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json accountForSessionNoLongerExists() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.AccountForSessionNoLongerExists"},
      {"Message",
       "The account for the current session has been removed, thus the current "
       "session has been removed as well."},
      {"Severity", "OK"},
      {"Resolution", "Attempt to connect with a valid account."}};
}

/**
 * @internal
 * @brief Formats CreateFailedMissingReqProperties message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json createFailedMissingReqProperties(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.CreateFailedMissingReqProperties"},
      {"Message", "The create operation failed because the required property " +
                      arg1 + " was missing from the request."},
      {"Severity", "Critical"},
      {"Resolution",
       "Correct the body to include the required property with a valid value "
       "and resubmit the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats PropertyValueFormatError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyValueFormatError(const std::string& arg1,
                                        const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyValueFormatError"},
      {"Message",
       "The value " + arg1 + " for the property " + arg2 +
           " is of a different format than the property can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the property in the request body and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats PropertyValueNotInList message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyValueNotInList(const std::string& arg1,
                                      const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyValueNotInList"},
      {"Message", "The value " + arg1 + " for the property " + arg2 +
                      " is not in the list of acceptable values."},
      {"Severity", "Warning"},
      {"Resolution",
       "Choose a value from the enumeration list that the implementation can "
       "support and resubmit the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ResourceAtUriInUnknownFormat message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceAtUriInUnknownFormat(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceAtUriInUnknownFormat"},
      {"Message", "The resource at " + arg1 +
                      " is in a format not recognized by the service."},
      {"Severity", "Critical"},
      {"Resolution",
       "Place an image or resource or file that is recognized by the service "
       "at the URI."}};
}

/**
 * @internal
 * @brief Formats ServiceInUnknownState message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json serviceInUnknownState() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ServiceInUnknownState"},
      {"Message",
       "The operation failed because the service is in an unknown state and "
       "can no longer take incoming requests."},
      {"Severity", "Critical"},
      {"Resolution",
       "Restart the service and resubmit the request if the operation "
       "failed."}};
}

/**
 * @internal
 * @brief Formats EventSubscriptionLimitExceeded message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json eventSubscriptionLimitExceeded() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.EventSubscriptionLimitExceeded"},
      {"Message",
       "The event subscription failed due to the number of simultaneous "
       "subscriptions exceeding the limit of the implementation."},
      {"Severity", "Critical"},
      {"Resolution",
       "Reduce the number of other subscriptions before trying to establish "
       "the event subscription or increase the limit of simultaneous "
       "subscriptions (if supported)."}};
}

/**
 * @internal
 * @brief Formats ActionParameterMissing message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterMissing(const std::string& arg1,
                                      const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterMissing"},
      {"Message", "The action " + arg1 + " requires the parameter " + arg2 +
                      " to be present in the request body."},
      {"Severity", "Critical"},
      {"Resolution",
       "Supply the action with the required parameter in the request body when "
       "the request is resubmitted."}};
}

/**
 * @internal
 * @brief Formats StringValueTooLong message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json stringValueTooLong(const std::string& arg1, const int& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.StringValueTooLong"},
      {"Message", "The string " + arg1 + " exceeds the length limit " +
                      std::to_string(arg2) + "."},
      {"Severity", "Warning"},
      {"Resolution",
       "Resubmit the request with an appropriate string length."}};
}

/**
 * @internal
 * @brief Formats PropertyValueTypeError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyValueTypeError(const std::string& arg1,
                                      const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyValueTypeError"},
      {"Message", "The value " + arg1 + " for the property " + arg2 +
                      " is of a different type than the property can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the property in the request body and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ResourceNotFound message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceNotFound(const std::string& arg1,
                                const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceNotFound"},
      {"Message", "The requested resource of type " + arg1 + " named " + arg2 +
                      " was not found."},
      {"Severity", "Critical"},
      {"Resolution",
       "Provide a valid resource identifier and resubmit the request."}};
}

/**
 * @internal
 * @brief Formats CouldNotEstablishConnection message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json couldNotEstablishConnection(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.CouldNotEstablishConnection"},
      {"Message", "The service failed to establish a Connection with the URI " +
                      arg1 + "."},
      {"Severity", "Critical"},
      {"Resolution",
       "Ensure that the URI contains a valid and reachable node name, protocol "
       "information and other URI components."}};
}

/**
 * @internal
 * @brief Formats PropertyNotWritable message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyNotWritable(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyNotWritable"},
      {"Message",
       "The property " + arg1 +
           " is a read only property and cannot be assigned a value."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the property from the request body and resubmit the request if "
       "the operation failed."}};
}

/**
 * @internal
 * @brief Formats QueryParameterValueTypeError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json queryParameterValueTypeError(const std::string& arg1,
                                            const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.QueryParameterValueTypeError"},
      {"Message", "The value " + arg1 + " for the query parameter " + arg2 +
                      " is of a different type than the parameter can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the query parameter in the request and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ServiceShuttingDown message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json serviceShuttingDown() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ServiceShuttingDown"},
      {"Message",
       "The operation failed because the service is shutting down and can no "
       "longer take incoming requests."},
      {"Severity", "Critical"},
      {"Resolution",
       "When the service becomes available, resubmit the request if the "
       "operation failed."}};
}

/**
 * @internal
 * @brief Formats ActionParameterDuplicate message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterDuplicate(const std::string& arg1,
                                        const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterDuplicate"},
      {"Message",
       "The action " + arg1 +
           " was submitted with more than one value for the parameter " + arg2 +
           "."},
      {"Severity", "Warning"},
      {"Resolution",
       "Resubmit the action with only one instance of the parameter in the "
       "request body if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ActionParameterNotSupported message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterNotSupported(const std::string& arg1,
                                           const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterNotSupported"},
      {"Message", "The parameter " + arg1 + " for the action " + arg2 +
                      " is not supported on the target resource."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the parameter supplied and resubmit the request if the "
       "operation failed."}};
}

/**
 * @internal
 * @brief Formats SourceDoesNotSupportProtocol message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json sourceDoesNotSupportProtocol(const std::string& arg1,
                                            const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.SourceDoesNotSupportProtocol"},
      {"Message", "The other end of the Connection at " + arg1 +
                      " does not support the specified protocol " + arg2 + "."},
      {"Severity", "Critical"},
      {"Resolution", "Change protocols or URIs. "}};
}

/**
 * @internal
 * @brief Formats AccountRemoved message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json accountRemoved() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.AccountRemoved"},
      {"Message", "The account was successfully removed."},
      {"Severity", "OK"},
      {"Resolution", "No resolution is required."}};
}

/**
 * @internal
 * @brief Formats AccessDenied message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json accessDenied(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.AccessDenied"},
      {"Message", "While attempting to establish a Connection to " + arg1 +
                      ", the service denied access."},
      {"Severity", "Critical"},
      {"Resolution",
       "Attempt to ensure that the URI is correct and that the service has the "
       "appropriate credentials."}};
}

/**
 * @internal
 * @brief Formats QueryNotSupported message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json queryNotSupported() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.QueryNotSupported"},
      {"Message", "Querying is not supported by the implementation."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the query parameters and resubmit the request if the operation "
       "failed."}};
}

/**
 * @internal
 * @brief Formats CreateLimitReachedForResource message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json createLimitReachedForResource() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.CreateLimitReachedForResource"},
      {"Message",
       "The create operation failed because the resource has reached the limit "
       "of possible resources."},
      {"Severity", "Critical"},
      {"Resolution",
       "Either delete resources and resubmit the request if the operation "
       "failed or do not resubmit the request."}};
}

/**
 * @internal
 * @brief Formats GeneralError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json generalError() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.GeneralError"},
      {"Message",
       "A general error has occurred. See ExtendedInfo for more information."},
      {"Severity", "Critical"},
      {"Resolution", "See ExtendedInfo for more information."}};
}

/**
 * @internal
 * @brief Formats Success message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json success() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.Success"},
      {"Message", "Successfully Completed Request"},
      {"Severity", "OK"},
      {"Resolution", "None"}};
}

/**
 * @internal
 * @brief Formats Created message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json created() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.Created"},
      {"Message", "The resource has been created successfully"},
      {"Severity", "OK"},
      {"Resolution", "None"}};
}

/**
 * @internal
 * @brief Formats PropertyUnknown message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyUnknown(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyUnknown"},
      {"Message",
       "The property " + arg1 +
           " is not in the list of valid properties for the resource."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the unknown property from the request body and resubmit the "
       "request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats NoValidSession message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json noValidSession() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.NoValidSession"},
      {"Message",
       "There is no valid session established with the implementation."},
      {"Severity", "Critical"},
      {"Resolution", "Establish as session before attempting any operations."}};
}

/**
 * @internal
 * @brief Formats InvalidObject message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json invalidObject(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.InvalidObject"},
      {"Message", "The object at " + arg1 + " is invalid."},
      {"Severity", "Critical"},
      {"Resolution",
       "Either the object is malformed or the URI is not correct.  Correct the "
       "condition and resubmit the request if it failed."}};
}

/**
 * @internal
 * @brief Formats ResourceInStandby message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceInStandby() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceInStandby"},
      {"Message",
       "The request could not be performed because the resource is in "
       "standby."},
      {"Severity", "Critical"},
      {"Resolution",
       "Ensure that the resource is in the correct power state and resubmit "
       "the request."}};
}

/**
 * @internal
 * @brief Formats ActionParameterValueTypeError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionParameterValueTypeError(const std::string& arg1,
                                             const std::string& arg2,
                                             const std::string& arg3) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionParameterValueTypeError"},
      {"Message", "The value " + arg1 + " for the parameter " + arg2 +
                      " in the action " + arg3 +
                      " is of a different type than the parameter can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the parameter in the request body and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats SessionLimitExceeded message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json sessionLimitExceeded() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.SessionLimitExceeded"},
      {"Message",
       "The session establishment failed due to the number of simultaneous "
       "sessions exceeding the limit of the implementation."},
      {"Severity", "Critical"},
      {"Resolution",
       "Reduce the number of other sessions before trying to establish the "
       "session or increase the limit of simultaneous sessions (if "
       "supported)."}};
}

/**
 * @internal
 * @brief Formats ActionNotSupported message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json actionNotSupported(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ActionNotSupported"},
      {"Message", "The action " + arg1 + " is not supported by the resource."},
      {"Severity", "Critical"},
      {"Resolution",
       "The action supplied cannot be resubmitted to the implementation.  "
       "Perhaps the action was invalid, the wrong resource was the target or "
       "the implementation documentation may be of assistance."}};
}

/**
 * @internal
 * @brief Formats InvalidIndex message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json invalidIndex(const int& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.InvalidIndex"},
      {"Message", "The index " + std::to_string(arg1) +
                      " is not a valid offset into the array."},
      {"Severity", "Warning"},
      {"Resolution",
       "Verify the index value provided is within the bounds of the array."}};
}

/**
 * @internal
 * @brief Formats EmptyJSON message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json emptyJSON() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.EmptyJSON"},
      {"Message",
       "The request body submitted contained an empty JSON object and the "
       "service is unable to process it."},
      {"Severity", "Warning"},
      {"Resolution",
       "Add properties in the JSON object and resubmit the request."}};
}

/**
 * @internal
 * @brief Formats QueryNotSupportedOnResource message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json queryNotSupportedOnResource() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.QueryNotSupportedOnResource"},
      {"Message", "Querying is not supported on the requested resource."},
      {"Severity", "Warning"},
      {"Resolution",
       "Remove the query parameters and resubmit the request if the operation "
       "failed."}};
}

/**
 * @internal
 * @brief Formats InsufficientPrivilege message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json insufficientPrivilege() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.InsufficientPrivilege"},
      {"Message",
       "There are insufficient privileges for the account or credentials "
       "associated with the current session to perform the requested "
       "operation."},
      {"Severity", "Critical"},
      {"Resolution",
       "Either abandon the operation or change the associated access rights "
       "and resubmit the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats PropertyValueModified message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyValueModified(const std::string& arg1,
                                     const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyValueModified"},
      {"Message", "The property " + arg1 + " was assigned the value " + arg2 +
                      " due to modification by the service."},
      {"Severity", "Warning"},
      {"Resolution", "No resolution is required."}};
}

/**
 * @internal
 * @brief Formats AccountNotModified message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json accountNotModified() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.AccountNotModified"},
      {"Message", "The account modification request failed."},
      {"Severity", "Warning"},
      {"Resolution",
       "The modification may have failed due to permission issues or issues "
       "with the request body."}};
}

/**
 * @internal
 * @brief Formats QueryParameterValueFormatError message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json queryParameterValueFormatError(const std::string& arg1,
                                              const std::string& arg2) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.QueryParameterValueFormatError"},
      {"Message",
       "The value " + arg1 + " for the parameter " + arg2 +
           " is of a different format than the parameter can accept."},
      {"Severity", "Warning"},
      {"Resolution",
       "Correct the value for the query parameter in the request and resubmit "
       "the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats PropertyMissing message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json propertyMissing(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.PropertyMissing"},
      {"Message",
       "The property " + arg1 +
           " is a required property and must be included in the request."},
      {"Severity", "Warning"},
      {"Resolution",
       "Ensure that the property is in the request body and has a valid value "
       "and resubmit the request if the operation failed."}};
}

/**
 * @internal
 * @brief Formats ResourceExhaustion message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json resourceExhaustion(const std::string& arg1) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.ResourceExhaustion"},
      {"Message", "The resource " + arg1 +
                      " was unable to satisfy the request "
                      "due to unavailability of "
                      "resources."},
      {"Severity", "Critical"},
      {"Resolution",
       "Ensure that the resources are available and resubmit the request."}};
}

/**
 * @internal
 * @brief Formats AccountModified message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json accountModified() {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.AccountModified"},
      {"Message", "The account was successfully modified."},
      {"Severity", "OK"},
      {"Resolution", "No resolution is required."}};
}

/**
 * @internal
 * @brief Formats QueryParameterOutOfRange message into JSON
 *
 * See header file for more information
 * @endinternal
 */
nlohmann::json queryParameterOutOfRange(const std::string& arg1,
                                        const std::string& arg2,
                                        const std::string& arg3) {
  return nlohmann::json{
      {"@odata.type", "/redfish/v1/$metadata#Message.v1_0_0.Message"},
      {"MessageId", "Base.1.2.0.QueryParameterOutOfRange"},
      {"Message", "The value " + arg1 + " for the query parameter " + arg2 +
                      " is out of range " + arg3 + "."},
      {"Severity", "Warning"},
      {"Resolution",
       "Reduce the value for the query parameter to a value that is within "
       "range, such as a start or count value that is within bounds of the "
       "number of resources in a collection or a page that is within the range "
       "of valid pages."}};
}

/*********************************
 * AUTOGENERATED FUNCTIONS END *
 *********************************/

}  // namespace messages

}  // namespace redfish
