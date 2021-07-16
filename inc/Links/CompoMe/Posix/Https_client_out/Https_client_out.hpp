#pragma once

#include "Data/CompoMe_Https.hpp"

#include "Links/Link.hpp"

#include "Links/CompoMe/Posix/Fake_pack.hpp"
// TYPES

#include "Types/CompoMe/String.hpp"

#include "Types/i32.hpp"
// STRUCT

// PORT

#include "Ports/CompoMe/Stream/out.hpp"

#include "Ports/CompoMe/Stream/map_out.hpp"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

namespace CompoMe {

namespace Posix {

class Https_client_out : public CompoMe::Link {
public:
  Https_client_out();
  virtual ~Https_client_out();

  void step() override;
  void main_connect() override;
  void main_disconnect() override;

  // one connect
  void one_connect(CompoMe::Require_helper &, CompoMe::String c) override;
  void one_connect(CompoMe::Interface &, CompoMe::String) override;

  // one disconnect
  void one_disconnect(CompoMe::Require_helper &, CompoMe::String) override;
  void one_disconnect(CompoMe::Interface &, CompoMe::String) override;

  // Get and set /////////////////////////////////////////////////////////////

  CompoMe::String get_addr() const;
  void set_addr(const CompoMe::String addr);
  CompoMe::String &a_addr();
  i32 get_port() const;
  void set_port(const i32 port);
  i32 &a_port();
  CompoMe::String get_to() const;
  void set_to(const CompoMe::String to);
  CompoMe::String &a_to();
  CompoMe::String get_ca_cert_file() const;
  void set_ca_cert_file(const CompoMe::String ca_cert_file);
  CompoMe::String &a_ca_cert_file();

  // Get Port /////////////////////////////////////////////////////////////

  CompoMe::Stream::out &get_main();
  CompoMe::Stream::map_out &get_many();

public:
  // Function
  i32 recv(char *buff, i32 size_buff);
  i32 send(const char *buff, i32 size_buff);
  // ///////////////////////////////////////////////////////////////////

private:
  std::map<CompoMe::String, struct CompoMe::Posix::Fake_pack> fake_many;

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;

  // DATA ////////////////////////////////////////////////////////////////////
  CompoMe::String addr;
  i32 port;
  CompoMe::String to;
  CompoMe::String ca_cert_file;

  // PORT ////////////////////////////////////////////////////////////////////
  CompoMe::Stream::out main;
  CompoMe::Stream::map_out many;
};

} // namespace Posix

} // namespace CompoMe
