#pragma once
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/eventstreamrpc/Exports.h>

#include <aws/crt/DateTime.h>
#include <aws/crt/StlAllocator.h>
#include <aws/crt/Types.h>
#include <aws/crt/UUID.h>
#include <aws/crt/io/EventLoopGroup.h>
#include <aws/crt/io/SocketOptions.h>
#include <aws/crt/io/TlsOptions.h>

#include <aws/event-stream/event_stream_rpc_client.h>

#include <atomic>
#include <functional>
#include <memory>

namespace Aws
{
    namespace Crt
    {
        namespace Io
        {
            class ClientBootstrap;
        }
    } // namespace Crt
    namespace Eventstreamrpc
    {
        class EventStreamHeader;
        class EventStreamRpcClient;
        class ClientConnection;
        class ClientContinuation;
        class MessageAmendment;

        using HeaderValueType = aws_event_stream_header_value_type;
        using MessageType = aws_event_stream_rpc_message_type;

        using OnMessageFlushCallback = std::function<void(int errorCode)>;

        /**
         * Allows the application to append headers and change the payload of the CONNECT
         * packet being sent out.
         */
        using ConnectMessageAmender = std::function<MessageAmendment &(void)>;

        class AWS_EVENTSTREAMRPC_API EventStreamHeader final
        {
          public:
            EventStreamHeader(const EventStreamHeader &lhs) noexcept;
            EventStreamHeader(EventStreamHeader &&rhs) noexcept;
            ~EventStreamHeader() noexcept;
            EventStreamHeader(const struct aws_event_stream_header_value_pair &header);
            EventStreamHeader(const Crt::String &name, bool value);
            EventStreamHeader(const Crt::String &name, int8_t value);
            EventStreamHeader(const Crt::String &name, int16_t value);
            EventStreamHeader(const Crt::String &name, int32_t value);
            EventStreamHeader(const Crt::String &name, int64_t value);
            EventStreamHeader(const Crt::String &name, Crt::DateTime &value);
            EventStreamHeader(
                const Crt::String &name,
                const Crt::String &value,
                Crt::Allocator *allocator = Crt::g_allocator) noexcept;
            EventStreamHeader(const Crt::String &name, Crt::ByteBuf &value);
            EventStreamHeader(const Crt::String &name, Crt::UUID value);

            HeaderValueType GetHeaderValueType();
            Crt::String GetHeaderName() noexcept;
            void SetHeaderName(Crt::String &);

            bool GetValueAsBoolean(bool &);
            bool GetValueAsByte(int8_t &);
            bool GetValueAsShort(int16_t &);
            bool GetValueAsInt(int32_t &);
            bool GetValueAsLong(int64_t &);
            bool GetValueAsTimestamp(Crt::DateTime &);
            bool GetValueAsBytes(Crt::ByteBuf &);
            bool GetValueAsUUID(Crt::UUID &);

            const struct aws_event_stream_header_value_pair *GetUnderlyingHandle() const;

            bool operator==(const EventStreamHeader &other) const noexcept;

          private:
            Crt::Allocator *m_allocator;
            Crt::ByteBuf m_valueByteBuf;
            struct aws_event_stream_header_value_pair m_underlyingHandle;
        };

        class AWS_EVENTSTREAMRPC_API MessageAmendment final
        {
          public:
            MessageAmendment() = default;
            MessageAmendment(const MessageAmendment &lhs) = default;
            MessageAmendment(MessageAmendment &&rhs) = default;
            explicit MessageAmendment(
                const Crt::List<EventStreamHeader> &headers,
                Crt::Optional<Crt::ByteBuf> &payload) noexcept;
            explicit MessageAmendment(const Crt::List<EventStreamHeader> &headers) noexcept;
            explicit MessageAmendment(Crt::List<EventStreamHeader> &&headers) noexcept;
            explicit MessageAmendment(const Crt::ByteBuf &payload) noexcept;
            void AddHeader(EventStreamHeader &&header) noexcept;
            void SetPayload(const Crt::Optional<Crt::ByteBuf> &payload) noexcept;
            Crt::List<EventStreamHeader> &GetHeaders() noexcept;
            Crt::Optional<Crt::ByteBuf> &GetPayload() noexcept;

          private:
            Crt::List<EventStreamHeader> m_headers;
            Crt::Optional<Crt::ByteBuf> m_payload;
        };

        /**
         * Configuration structure holding all options relating to eventstream RPC connection establishment
         */
        class AWS_EVENTSTREAMRPC_API ClientConnectionOptions final
        {
          public:
            ClientConnectionOptions();
            ClientConnectionOptions(const ClientConnectionOptions &rhs) = default;
            ClientConnectionOptions(ClientConnectionOptions &&rhs) = default;

            ~ClientConnectionOptions() = default;

            ClientConnectionOptions &operator=(const ClientConnectionOptions &rhs) = default;
            ClientConnectionOptions &operator=(ClientConnectionOptions &&rhs) = default;

            Crt::Io::ClientBootstrap *Bootstrap;
            Crt::Io::SocketOptions SocketOptions;
            Crt::Optional<Crt::Io::TlsConnectionOptions> TlsOptions;
            Crt::String HostName;
            uint16_t Port;
        };

        class AWS_EVENTSTREAMRPC_API ConnectionLifecycleHandler
        {
          public:
            /**
             * This callback is only invoked upon receiving a CONNECT_ACK with the
             * CONNECTION_ACCEPTED flag set by the server. Therefore, once this callback
             * is invoked, the `ClientConnection` is ready to be used for sending messages.
             */
            virtual void OnConnectCallback();
            /**
             * Invoked upon connection shutdown. `errorCode` will specify
             * shutdown reason. A graceful connection close will set `errorCode` to
             * `AWS_ERROR_SUCCESS` or 0.
             */
            virtual void OnDisconnectCallback(int errorCode);
            /**
             * Invoked upon receiving any connection error. Use the return value to determine
             * whether or not to force the connection to close. Keep in mind that once
             * closed, the `ClientConnection` can no longer send messages.
             */
            virtual bool OnErrorCallback(int errorCode);
            /**
             * Invoked upon receiving a ping from the server. The `headers` and `payload`
             * refer to what is contained in the ping message.
             */
            virtual void OnPingCallback(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload);
        };

        class AWS_EVENTSTREAMRPC_API ClientContinuationHandler
        {
          public:
            /**
             * Invoked when a message is received on this continuation.
             */
            virtual void OnContinuationMessage(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                MessageType messageType,
                uint32_t messageFlags) = 0;
            /**
             * Invoked when the continuation is closed.
             *
             * Once the continuation is closed, no more messages may be sent or received.
             * The continuation is closed when a message is sent or received with
             * the TERMINATE_STREAM flag, or when the connection shuts down.
             */
            virtual void OnContinuationClosed() = 0;
        };

        class AWS_EVENTSTREAMRPC_API ClientConnection final
        {
          public:
            enum ConnectStatus
            {
                /* If error messages are added to `aws_event_stream_errors`, this will need to be updated. */
                AWS_ERROR_EVENT_STREAM_RPC_UNKNOWN_PROTOCOL_MESSAGE =
                    AWS_ERROR_EVENT_STREAM_RPC_STREAM_NOT_ACTIVATED + 1
            };
            ClientConnection(Crt::Allocator *allocator) noexcept;
            ~ClientConnection() noexcept;
            ClientConnection(const ClientConnection &) = delete;
            ClientConnection(ClientConnection &&) = delete;
            ClientConnection &operator=(const ClientConnection &) = delete;
            ClientConnection &operator=(ClientConnection &&) = delete;

            bool Connect(
                const ClientConnectionOptions &connectionOptions,
                ConnectionLifecycleHandler *connectionLifecycleHandler,
                ConnectMessageAmender connectMessageAmender) noexcept;

            void SendPing(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

            void SendPingResponse(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

            ClientContinuation NewStream(ClientContinuationHandler *clientContinuationHandler) noexcept;

            void Close() noexcept;
            void Close(int errorCode) noexcept;

            /**
             * @return true if the instance is in a valid state, false otherwise.
             */
            operator bool() const noexcept;
            /**
             * @return the value of the last aws error encountered by operations on this instance.
             */
            int LastError() const noexcept;

          private:
            friend class ClientContinuation;
            enum ClientState
            {
                DISCONNECTED = 1,
                CONNECTING_TO_SOCKET,
                WAITING_FOR_CONNECT_ACK,
                CONNECTED,
                DISCONNECTING,
            };
            Crt::Allocator *m_allocator;
            struct aws_event_stream_rpc_client_connection *m_underlyingConnection;
            ClientState m_clientState;
            ConnectionLifecycleHandler *m_lifecycleHandler;
            ConnectMessageAmender m_connectMessageAmender;
            static void s_customDeleter(ClientConnection *connection) noexcept;
            void SendProtocolMessage(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                MessageType messageType,
                uint32_t messageFlags,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

            static void s_onConnectionShutdown(
                struct aws_event_stream_rpc_client_connection *connection,
                int errorCode,
                void *userData) noexcept;
            static void s_onConnectionSetup(
                struct aws_event_stream_rpc_client_connection *connection,
                int errorCode,
                void *userData) noexcept;
            static void s_onProtocolMessage(
                struct aws_event_stream_rpc_client_connection *connection,
                const struct aws_event_stream_rpc_message_args *messageArgs,
                void *userData) noexcept;

            static void s_protocolMessageCallback(int errorCode, void *userData) noexcept;
            static void s_sendProtocolMessage(
                ClientConnection *connection,
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                MessageType messageType,
                uint32_t messageFlags,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

            static void s_sendPing(
                ClientConnection *connection,
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

            static void s_sendPingResponse(
                ClientConnection *connection,
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;
        };

        class AWS_EVENTSTREAMRPC_API ClientContinuation final
        {
          public:
            ClientContinuation(
                ClientConnection *connection,
                ClientContinuationHandler *handler,
                Crt::Allocator *allocator) noexcept;
            ~ClientContinuation() noexcept;
            void Activate(
                const Crt::String &operation,
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                MessageType messageType,
                uint32_t messageFlags,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;
            bool IsClosed() noexcept;
            void SendMessage(
                const Crt::List<EventStreamHeader> &headers,
                const Crt::Optional<Crt::ByteBuf> &payload,
                MessageType messageType,
                uint32_t messageFlags,
                OnMessageFlushCallback onMessageFlushCallback) noexcept;

          private:
            Crt::Allocator *m_allocator;
            ClientContinuationHandler *m_handler;
            struct aws_event_stream_rpc_client_continuation_token *m_continuationToken;
            static void s_onContinuationMessage(
                struct aws_event_stream_rpc_client_continuation_token *continuationToken,
                const struct aws_event_stream_rpc_message_args *messageArgs,
                void *userData) noexcept;
            static void s_onContinuationClosed(
                struct aws_event_stream_rpc_client_continuation_token *continuationToken,
                void *userData) noexcept;
        };

        class AWS_EVENTSTREAMRPC_API AbstractShapeBase
        {
        };

        /**
         * Base class for all operation stream handlers.
         * For operations with a streaming response (0+ messages that may arrive
         * after the initial response).
         */
        class AWS_EVENTSTREAMRPC_API StreamResponseHandler
        {
          public:
            /**
             * Invoked when a message is received on this continuation.
             */
            virtual void OnStreamEvent(AbstractShapeBase *shape);
            /**
             * Invoked when a message is received on this continuation.
             *
             * This callback can return true so that the connection is closed afterwards.
             */
            virtual bool OnStreamError(int errorCode);
            /**
             * Invoked when stream is closed, so no more messages will be receivied.
             */
            virtual void OnStreamClosed();
        };

        class AWS_EVENTSTREAMRPC_API ClientOperation
        {
          public:
            ClientOperation(ClientConnection &connection, StreamResponseHandler *streamHandler) noexcept;
            void Close(OnMessageFlushCallback onMessageFlushCallback) noexcept;

          protected:
            void FindHeaderByName(const Crt::List<EventStreamHeader> &headers, Crt::String &name) noexcept;
            void Activate(AbstractShapeBase *shape, OnMessageFlushCallback onMessageFlushCallback) noexcept;
            void SendStreamEvent(AbstractShapeBase *shape, OnMessageFlushCallback onMessageFlushCallback) noexcept;

          private:
            class AWS_EVENTSTREAMRPC_API OperationContinuationHandler : public ClientContinuationHandler
            {
              public:
                OperationContinuationHandler() = default;
                /**
                 * Invoked when a message is received on this continuation.
                 */
                void OnContinuationMessage(
                    const Crt::List<EventStreamHeader> &headers,
                    const Crt::Optional<Crt::ByteBuf> &payload,
                    MessageType messageType,
                    uint32_t messageFlags) override
                {
                }
                /**
                 * Invoked when the continuation is closed.
                 *
                 * Once the continuation is closed, no more messages may be sent or received.
                 * The continuation is closed when a message is sent or received with
                 * the TERMINATE_STREAM flag, or when the connection shuts down.
                 */
                void OnContinuationClosed() override {}
            };
            uint32_t m_messageCount;
            StreamResponseHandler *m_streamHandler;
            OperationContinuationHandler m_operationContinuationHandler;
            ClientContinuation m_clientContinuation;
        };
    } // namespace Eventstreamrpc
} // namespace Aws