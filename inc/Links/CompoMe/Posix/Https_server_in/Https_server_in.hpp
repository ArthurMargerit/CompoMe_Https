#pragma once

#include "Data/CompoMe_Https.hpp"

#include "Links/Link.hpp"

// TYPES

#include "Types/CompoMe/String.hpp"

#include "Types/i32.hpp"

#include "Types/ui32.hpp"
// STRUCT

// PORT

#include "Ports/CompoMe/Stream/in.hpp"

#include "Ports/CompoMe/Stream/map_in.hpp"


#include <stdlib.h>
#include <string.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <poll.h>

namespace CompoMe {

namespace Posix {

class Https_server_in : public CompoMe::Link {
public:
  Https_server_in();
  virtual ~Https_server_in();

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
  ui32 get_max_client() const;
  void set_max_client(const ui32 max_client);
  ui32 &a_max_client();
  ui32 get_max_request_size() const;
  void set_max_request_size(const ui32 max_request_size);
  ui32 &a_max_request_size();
  CompoMe::String get_cert_file() const;
  void set_cert_file(const CompoMe::String cert_file);
  CompoMe::String &a_cert_file();
  CompoMe::String get_key_file() const;
  void set_key_file(const CompoMe::String key_file);
  CompoMe::String &a_key_file();

  // Get Port /////////////////////////////////////////////////////////////

  CompoMe::Stream::in &get_main();
  CompoMe::Stream::map_in &get_many();

public:
  // Function

  // ///////////////////////////////////////////////////////////////////

private:
  bool accept();
  bool write(int i, const std::string &r);
  bool read(int i);
  void one_disconnect(int i);

  struct pollfd *fds;
  mbedtls_net_context *ssl_fds;
  ui32 i_fds;
  unsigned char *buf;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_ssl_context *ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;

  // DATA ////////////////////////////////////////////////////////////////////
  CompoMe::String addr;
  i32 port;
  ui32 max_client;
  ui32 max_request_size;
  CompoMe::String cert_file;
  CompoMe::String key_file;

  // PORT ////////////////////////////////////////////////////////////////////
  CompoMe::Stream::in main;
  CompoMe::Stream::map_in many;
};

} // namespace Posix

} // namespace CompoMe
