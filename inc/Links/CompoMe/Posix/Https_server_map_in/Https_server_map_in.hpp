#pragma once

#include "Links/Link.hpp"

// TYPES

#include "Types/CompoMe/String.hpp"

#include "Types/i32.hpp"

#include "Types/ui32.hpp"
// STRUCT

namespace CompoMe {
class Function_stream;
class Return_stream;
class Interface;
} // namespace CompoMe

#include "Data/CompoMe_Https.hpp"

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

class Https_server_map_in : public CompoMe::Link, public CompoMe::Link_map_in {
public:
  Https_server_map_in();
  virtual ~Https_server_map_in();

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
  virtual ui32 get_max_client() const;
  virtual void set_max_client(const ui32 max_client);
  ui32 &a_max_client();
  virtual ui32 get_max_request_size() const;
  virtual void set_max_request_size(const ui32 max_request_size);
  ui32 &a_max_request_size();
  virtual CompoMe::String get_cert_file() const;
  virtual void set_cert_file(const CompoMe::String cert_file);
  CompoMe::String &a_cert_file();
  virtual CompoMe::String get_key_file() const;
  virtual void set_key_file(const CompoMe::String key_file);
  CompoMe::String &a_key_file();

public:
  // Function
  // ///////////////////////////////////////////////////////////////////
private:
  bool accept();
  bool read(int );
  bool write(int ,const std::string&);
  void disconnect(int );

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
};

} // namespace Posix

} // namespace CompoMe
