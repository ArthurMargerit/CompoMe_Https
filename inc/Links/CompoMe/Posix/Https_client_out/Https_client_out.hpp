#pragma once

#include "Links/Link.hpp"

// TYPES

#include "Types/CompoMe/String.hpp"

#include "Types/i32.hpp"
// STRUCT

namespace CompoMe {
class Function_stream;
class Return_stream;
class Interface;
} // namespace CompoMe

#include "Data/CompoMe_Https.hpp"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
namespace CompoMe {

namespace Posix {
  class Https_client_out;
  namespace Https_client_out_ns {
    class Function_string_stream_send : public CompoMe::Function_stream_send {
    private:
      std::stringstream a_ss;
      Https_client_out &a_l;

    public:
      Function_string_stream_send(Https_client_out &p_l);
      void start() final;
      void send() final;
      std::ostream &get_so() override { return this->a_ss; }
    };

    class Return_string_stream_recv : public CompoMe::Return_stream_recv {
    private:
      std::stringstream a_ss;
      Https_client_out &a_l;

    public:
      Return_string_stream_recv(Https_client_out &p_l);
      void pull() final;
      void end() final;
      std::istream &get_si() override { return this->a_ss; }
    };
  } // namespace Http_client_out_ns

class Https_client_out : public CompoMe::Link, public CompoMe::Link_out {
public:
  Https_client_out();
  virtual ~Https_client_out();

  void step() override;
  void connect() override;
  void disconnect() override;

  // Get and set /////////////////////////////////////////////////////////////

  virtual CompoMe::String get_addr() const;
  virtual void set_addr(const CompoMe::String addr);
  CompoMe::String &a_addr();
  virtual i32 get_port() const;
  virtual void set_port(const i32 port);
  i32 &a_port();
  virtual CompoMe::String get_to() const;
  virtual void set_to(const CompoMe::String to);
  CompoMe::String &a_to();
  virtual CompoMe::String get_ca_cert_file() const;
  virtual void set_ca_cert_file(const CompoMe::String ca_cert_file);
  CompoMe::String &a_ca_cert_file();

public:
  // Function
  i32 send(const char * buff, i32 size_buff );
  i32 recv(char * buff, i32 size_buff );

  // ///////////////////////////////////////////////////////////////////
private:
  CompoMe::Fake_stream *f;

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;

  Https_client_out_ns::Function_string_stream_send fss;
  Https_client_out_ns::Return_string_stream_recv rsr;

  // DATA ////////////////////////////////////////////////////////////////////

  CompoMe::String addr;

  i32 port;

  CompoMe::String to;

  CompoMe::String ca_cert_file;
};

} // namespace Posix

} // namespace CompoMe
