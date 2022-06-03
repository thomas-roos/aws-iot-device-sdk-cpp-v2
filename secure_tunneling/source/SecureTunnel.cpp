/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/crt/Api.h>
#include <aws/iotsecuretunneling/SecureTunnel.h>

namespace Aws
{
    namespace Iotsecuretunneling
    {
        SecureTunnelBuilder::SecureTunnelBuilder(
            Crt::Allocator *allocator,                        // Should out live this object
            Aws::Crt::Io::ClientBootstrap &clientBootstrap,   // Should out live this object
            const Aws::Crt::Io::SocketOptions &socketOptions, // Make a copy and save in this object
            const std::string &accessToken,                   // Make a copy and save in this object
            aws_secure_tunneling_local_proxy_mode localProxyMode,
            const std::string &endpointHost) // Make a copy and save in this object
            : m_allocator(allocator), m_clientBootstrap(&clientBootstrap), m_socketOptions(socketOptions),
              m_accessToken(accessToken), m_localProxyMode(localProxyMode), m_endpointHost(endpointHost), m_rootCa(""),
              m_httpClientConnectionProxyOptions(), m_OnConnectionComplete(), m_OnConnectionShutdown(),
              m_OnSendDataComplete(), m_OnDataReceive(), m_OnStreamStart(), m_OnStreamReset(), m_OnSessionReset()
        {
        }

        SecureTunnelBuilder::SecureTunnelBuilder(
            Crt::Allocator *allocator,                        // Should out live this object
            const Aws::Crt::Io::SocketOptions &socketOptions, // Make a copy and save in this object
            const std::string &accessToken,                   // Make a copy and save in this object
            aws_secure_tunneling_local_proxy_mode localProxyMode,
            const std::string &endpointHost) // Make a copy and save in this object
            : m_allocator(allocator), m_clientBootstrap(Crt::ApiHandle::GetOrCreateStaticDefaultClientBootstrap()),
              m_socketOptions(socketOptions), m_accessToken(accessToken), m_localProxyMode(localProxyMode),
              m_endpointHost(endpointHost), m_rootCa(""), m_httpClientConnectionProxyOptions(),
              m_OnConnectionComplete(), m_OnConnectionShutdown(), m_OnSendDataComplete(), m_OnDataReceive(),
              m_OnStreamStart(), m_OnStreamReset(), m_OnSessionReset()
        {
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithRootCa(const std::string &rootCa)
        {
            m_rootCa = rootCa;
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithHttpClientConnectionProxyOptions(
            const Aws::Crt::Http::HttpClientConnectionProxyOptions &httpClientConnectionProxyOptions)
        {
            m_httpClientConnectionProxyOptions = httpClientConnectionProxyOptions;
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnConnectionComplete(OnConnectionComplete onConnectionComplete)
        {
            m_OnConnectionComplete = std::move(onConnectionComplete);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnConnectionShutdown(OnConnectionShutdown onConnectionShutdown)
        {
            m_OnConnectionShutdown = std::move(onConnectionShutdown);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnSendDataComplete(OnSendDataComplete onSendDataComplete)
        {
            m_OnSendDataComplete = std::move(onSendDataComplete);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnDataReceive(OnDataReceive onDataReceive)
        {
            m_OnDataReceive = std::move(onDataReceive);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnStreamStart(OnStreamStart onStreamStart)
        {
            m_OnStreamStart = std::move(onStreamStart);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnStreamReset(OnStreamReset onStreamReset)
        {
            m_OnStreamReset = std::move(onStreamReset);
            return *this;
        }

        SecureTunnelBuilder &SecureTunnelBuilder::WithOnSessionReset(OnSessionReset onSessionReset)
        {
            m_OnSessionReset = std::move(onSessionReset);
            return *this;
        }

        std::shared_ptr<SecureTunnel> SecureTunnelBuilder::Build() noexcept
        {
            auto tunnel = std::shared_ptr<SecureTunnel>(new SecureTunnel(
                m_allocator,
                m_clientBootstrap,
                m_socketOptions,
                m_accessToken,
                m_localProxyMode,
                m_endpointHost,
                m_rootCa,
                m_httpClientConnectionProxyOptions.has_value() ? &m_httpClientConnectionProxyOptions.value() : nullptr,
                m_OnConnectionComplete,
                m_OnConnectionShutdown,
                m_OnSendDataComplete,
                m_OnDataReceive,
                m_OnStreamStart,
                m_OnStreamReset,
                m_OnSessionReset));

            if (tunnel->m_secure_tunnel == nullptr)
            {
                return nullptr;
            }

            return tunnel;
        }

        class SecureTunnelBinding
        {
          public:
            SecureTunnelBinding(void) = delete;
            SecureTunnelBinding(SecureTunnelBinding &&other) = delete;
            SecureTunnelBinding(const SecureTunnelBinding &other) = delete;

            SecureTunnelBinding &operator=(const SecureTunnelBinding &rhs) = delete;
            SecureTunnelBinding &operator=(SecureTunnelBinding &&rhs) = delete;

            SecureTunnelBinding(
                struct aws_allocator *allocator,
                OnConnectionComplete onConnectionComplete,
                OnConnectionShutdown onConnectionShutdown,
                OnSendDataComplete onSendDataComplete,
                OnDataReceive onDataReceive,
                OnStreamStart onStreamStart,
                OnStreamReset onStreamReset,
                OnSessionReset onSessionReset,
                std::shared_ptr<std::promise<void>> terminationComplete)
                : m_Allocator(allocator), m_OnConnectionComplete(std::move(onConnectionComplete)),
                  m_OnConnectionShutdown(std::move(onConnectionShutdown)),
                  m_OnSendDataComplete(std::move(onSendDataComplete)), m_OnDataReceive(std::move(onDataReceive)),
                  m_OnStreamStart(std::move(onStreamStart)), m_OnStreamReset(std::move(onStreamReset)),
                  m_OnSessionReset(std::move(onSessionReset)), m_TerminationComplete(terminationComplete)
            {
            }

            virtual ~SecureTunnelBinding() { m_TerminationComplete->set_value(); }

            struct aws_allocator *m_Allocator;

            OnConnectionComplete m_OnConnectionComplete;
            OnConnectionShutdown m_OnConnectionShutdown;
            OnSendDataComplete m_OnSendDataComplete;
            OnDataReceive m_OnDataReceive;
            OnStreamStart m_OnStreamStart;
            OnStreamReset m_OnStreamReset;
            OnSessionReset m_OnSessionReset;

            std::shared_ptr<std::promise<void>> m_TerminationComplete;
        };

        static void s_OnConnectionComplete(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnConnectionComplete)
            {
                secureTunnelBinding->m_OnConnectionComplete();
            }
        }

        static void s_OnConnectionShutdown(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnConnectionShutdown)
            {
                secureTunnelBinding->m_OnConnectionShutdown();
            }
        }

        static void s_OnSendDataComplete(int error_code, void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnSendDataComplete)
            {
                secureTunnelBinding->m_OnSendDataComplete(error_code);
            }
        }

        static void s_OnDataReceive(const struct aws_byte_buf *data, void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnDataReceive)
            {
                secureTunnelBinding->m_OnDataReceive(*data);
            }
        }

        static void s_OnStreamStart(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnStreamStart)
            {
                secureTunnelBinding->m_OnStreamStart();
            }
        }

        static void s_OnStreamReset(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnStreamReset)
            {
                secureTunnelBinding->m_OnStreamReset();
            }
        }

        static void s_OnSessionReset(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            if (secureTunnelBinding->m_OnSessionReset)
            {
                secureTunnelBinding->m_OnSessionReset();
            }
        }

        static void s_OnTerminationComplete(void *user_data)
        {
            auto *secureTunnelBinding = static_cast<SecureTunnelBinding *>(user_data);
            Aws::Crt::Delete(secureTunnelBinding, secureTunnelBinding->m_Allocator);
        }

        /**
         * Private SecureTunnel constructor used by SecureTunnelBuilder on SecureTunnelBuilder::Build() and by old
         * SecureTunnel constructor which should be deprecated
         */
        SecureTunnel::SecureTunnel(
            Crt::Allocator *allocator,
            Aws::Crt::Io::ClientBootstrap *clientBootstrap,
            const Aws::Crt::Io::SocketOptions &socketOptions,
            const std::string &accessToken,
            aws_secure_tunneling_local_proxy_mode localProxyMode,
            const std::string &endpointHost,

            const std::string &rootCa,
            Aws::Crt::Http::HttpClientConnectionProxyOptions *httpClientConnectionProxyOptions,

            OnConnectionComplete onConnectionComplete,
            OnConnectionShutdown onConnectionShutdown,
            OnSendDataComplete onSendDataComplete,
            OnDataReceive onDataReceive,
            OnStreamStart onStreamStart,
            OnStreamReset onStreamReset,
            OnSessionReset onSessionReset)
            : m_TerminationComplete(Aws::Crt::MakeShared<std::promise<void>>(allocator))
        {
            // Initialize aws_secure_tunnel_options
            aws_secure_tunnel_options config;
            AWS_ZERO_STRUCT(config);

            config.allocator = allocator;
            config.bootstrap = clientBootstrap ? clientBootstrap->GetUnderlyingHandle() : nullptr;
            config.socket_options = &socketOptions.GetImpl();

            config.access_token = aws_byte_cursor_from_c_str(accessToken.c_str());
            config.local_proxy_mode = localProxyMode;
            config.endpoint_host = aws_byte_cursor_from_c_str(endpointHost.c_str());

            if (rootCa.length() > 0)
            {
                config.root_ca = rootCa.c_str();
            }

            config.on_connection_complete = s_OnConnectionComplete;
            config.on_connection_shutdown = s_OnConnectionShutdown;
            config.on_send_data_complete = s_OnSendDataComplete;
            config.on_data_receive = s_OnDataReceive;
            config.on_stream_start = s_OnStreamStart;
            config.on_stream_reset = s_OnStreamReset;
            config.on_session_reset = s_OnSessionReset;
            config.on_termination_complete = s_OnTerminationComplete;

            config.user_data = this;

            aws_http_proxy_options temp;
            AWS_ZERO_STRUCT(temp);
            if (httpClientConnectionProxyOptions != NULL)
            {
                httpClientConnectionProxyOptions->InitializeRawProxyOptions(temp);
                config.http_proxy_options = &temp;
            }

            auto binding = Aws::Crt::New<SecureTunnelBinding>(
                allocator,
                allocator,
                onConnectionComplete,
                onConnectionShutdown,
                onSendDataComplete,
                onDataReceive,
                onStreamStart,
                onStreamReset,
                onSessionReset,
                m_TerminationComplete);
            config.user_data = binding;

            // Create the secure tunnel
            m_secure_tunnel = aws_secure_tunnel_new(&config);
            if (m_secure_tunnel == nullptr)
            {
                Aws::Crt::Delete(binding, allocator);
            }
        }

        /**
         * Should be deprecated when possible.
         * SecureTunnelBuilder::Build() should be used to generate new SecureTunnels
         */
        SecureTunnel::SecureTunnel(
            Crt::Allocator *allocator,
            Aws::Crt::Io::ClientBootstrap *clientBootstrap,
            const Aws::Crt::Io::SocketOptions &socketOptions,

            const std::string &accessToken,
            aws_secure_tunneling_local_proxy_mode localProxyMode,
            const std::string &endpointHost,
            const std::string &rootCa,

            OnConnectionComplete onConnectionComplete,
            OnConnectionShutdown onConnectionShutdown,
            OnSendDataComplete onSendDataComplete,
            OnDataReceive onDataReceive,
            OnStreamStart onStreamStart,
            OnStreamReset onStreamReset,
            OnSessionReset onSessionReset)
            : SecureTunnel(
                  allocator,
                  clientBootstrap,
                  socketOptions,
                  accessToken,
                  localProxyMode,
                  endpointHost,
                  rootCa,
                  nullptr,
                  onConnectionComplete,
                  onConnectionShutdown,
                  onSendDataComplete,
                  onDataReceive,
                  onStreamStart,
                  onStreamReset,
                  onSessionReset)
        {
        }

        /**
         * Should be deprecated when possible.
         * SecureTunnelBuilder::Build() should be used to generate new SecureTunnels
         */
        SecureTunnel::SecureTunnel(
            Crt::Allocator *allocator,
            const Aws::Crt::Io::SocketOptions &socketOptions,

            const std::string &accessToken,
            aws_secure_tunneling_local_proxy_mode localProxyMode,
            const std::string &endpointHost,
            const std::string &rootCa,

            OnConnectionComplete onConnectionComplete,
            OnConnectionShutdown onConnectionShutdown,
            OnSendDataComplete onSendDataComplete,
            OnDataReceive onDataReceive,
            OnStreamStart onStreamStart,
            OnStreamReset onStreamReset,
            OnSessionReset onSessionReset)
            : SecureTunnel(
                  allocator,
                  Crt::ApiHandle::GetOrCreateStaticDefaultClientBootstrap(),
                  socketOptions,
                  accessToken,
                  localProxyMode,
                  endpointHost,
                  rootCa,
                  nullptr,
                  onConnectionComplete,
                  onConnectionShutdown,
                  onSendDataComplete,
                  onDataReceive,
                  onStreamStart,
                  onStreamReset,
                  onSessionReset)
        {
        }

        SecureTunnel::SecureTunnel(SecureTunnel &&other) noexcept
        {
            m_TerminationComplete = std::move(other.m_TerminationComplete);

            m_secure_tunnel = other.m_secure_tunnel;
            other.m_secure_tunnel = nullptr;
        }

        SecureTunnel::~SecureTunnel()
        {
            if (m_secure_tunnel)
            {
                aws_secure_tunnel_release(m_secure_tunnel);
            }
        }

        SecureTunnel &SecureTunnel::operator=(SecureTunnel &&other) noexcept
        {
            if (this != &other)
            {
                this->~SecureTunnel();

                m_TerminationComplete = std::move(other.m_TerminationComplete);

                m_secure_tunnel = other.m_secure_tunnel;
                other.m_secure_tunnel = nullptr;
            }

            return *this;
        }

        bool SecureTunnel::IsValid() { return m_secure_tunnel ? true : false; }

        int SecureTunnel::Connect() { return aws_secure_tunnel_connect(m_secure_tunnel); }

        int SecureTunnel::Close() { return aws_secure_tunnel_close(m_secure_tunnel); }

        int SecureTunnel::SendData(const Crt::ByteCursor &data)
        {
            return aws_secure_tunnel_send_data(m_secure_tunnel, &data);
        }

        int SecureTunnel::SendStreamStart() { return aws_secure_tunnel_stream_start(m_secure_tunnel); }

        int SecureTunnel::SendStreamReset() { return aws_secure_tunnel_stream_reset(m_secure_tunnel); }

        aws_secure_tunnel *SecureTunnel::GetUnderlyingHandle() { return m_secure_tunnel; }

        void SecureTunnel::Shutdown()
        {
            Close();
            aws_secure_tunnel_release(m_secure_tunnel);
            m_secure_tunnel = nullptr;

            m_TerminationComplete->get_future().wait();
        }
    } // namespace Iotsecuretunneling
} // namespace Aws
