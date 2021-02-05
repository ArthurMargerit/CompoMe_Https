#include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"

#include "Interfaces/Interface.hpp"
#include "Links/atomizes.hpp"
#include "CompoMe/Log.hpp"
#include <cstring>


namespace CompoMe {

namespace Posix {
  const char *pers = "ssl_client1";

  Https_client_out::Https_client_out() : CompoMe::Link(),fss(*this), rsr(*this), f(nullptr) {
  int ret;
  mbedtls_net_init( &this->server_fd );
  mbedtls_ssl_init( &this->ssl );
  mbedtls_ssl_config_init( &this->conf );
  mbedtls_x509_crt_init( &this->cacert );
  mbedtls_ctr_drbg_init( &this->ctr_drbg );
  mbedtls_entropy_init( &this->entropy );
  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen( pers ) ) ) != 0 ) {
      C_ERROR( " ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

}

Https_client_out::~Https_client_out() {
  mbedtls_net_free( &this->server_fd );

  mbedtls_x509_crt_free( &this->cacert );
  mbedtls_ssl_free( &this->ssl );
  mbedtls_ssl_config_free( &this->conf );
  mbedtls_ctr_drbg_free( &this->ctr_drbg );
  mbedtls_entropy_free( &this->entropy );
}

void Https_client_out::step() { Link::step(); }

  i32 Https_client_out::send(const char * buff,
                             i32 size_buff ) {

    int ret;
    while( ( ret = mbedtls_ssl_write( &this->ssl, (const unsigned char*)buff, size_buff ) ) <= 0 )
      {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            C_ERROR("mbedtls_ssl_write returned %d", ret);
            return -1;
          }
      }

    return 0;
  }

  i32 Https_client_out::recv(char * buff,
                             i32 size_buff ) {
    int len;
    do {
      int ret = mbedtls_ssl_read( &this->ssl, (unsigned char *)buff, size_buff-1 );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
          continue;
        }

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
          C_ERROR("MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")
          return -1;
        }

        if( ret < 0 ) {
            C_ERROR( "! mbedtls_ssl_read returned %d", ret );
            return -1;
          }

        if( ret == 0 ) {
            break;
          }

        len = ret;
        break;
      } while(1);

    buff[len] = '\0';
    return len;
  }


void Https_client_out::connect() { Link::connect();
  int ret = mbedtls_x509_crt_parse_file(&this->cacert, this->get_ca_cert_file().str.c_str());
  if( ret < 0 ) {
      C_ERROR("! mbedtls_x509_crt_parse returned %d", ret );
      return;
    }

  std::stringstream ss;
  ss << this->get_port();
  ret = mbedtls_net_connect(&this->server_fd,
                            this->get_addr().str.c_str(),
                            ss.str().c_str(),
                            MBEDTLS_NET_PROTO_TCP);
  if( ret != 0 ) {
      C_ERROR( "! mbedtls_net_connect returned %d", ret);
      return;
    }

  ret = mbedtls_ssl_config_defaults( &this->conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
  if( ret != 0 ) {
      C_ERROR( "! mbedtls_ssl_config_defaults returned %d", ret );
      return;
    }

  /* OPTIONAL is not optimal for security,
   * but makes interop easier in this simplified example */
  mbedtls_ssl_conf_authmode( &this->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
  mbedtls_ssl_conf_ca_chain( &this->conf, &this->cacert, NULL );
  mbedtls_ssl_conf_rng( &this->conf, mbedtls_ctr_drbg_random, &this->ctr_drbg );
  ret = mbedtls_ssl_setup( &this->ssl, &this->conf );
  if( ret != 0 ) {
      C_ERROR( "! mbedtls_ssl_setup returned %d", ret);
      return;
  }

  ret = mbedtls_ssl_set_hostname(&this->ssl, this->get_addr().str.c_str());
  if( ret != 0 ) {
      C_ERROR( "! mbedtls_ssl_set_hostname returned %d", ret );
      return;
  }

  mbedtls_ssl_set_bio( &this->ssl, &this->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  /*
   * 4. Handshake
   */
  while( ( ret = mbedtls_ssl_handshake( &this->ssl ) ) != 0 ) {
      if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
          C_ERROR( "! mbedtls_ssl_handshake returned -0x%x", (unsigned int) -ret );
          return ;
        }
    }

  /*
   * 5. Verify the server certificate
   */
  uint32_t flags;
  flags = mbedtls_ssl_get_verify_result( &this->ssl );
  if( flags != 0 ) {
      char vrfy_buf[512];
      mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
      C_WARNING(vrfy_buf);
    }

  this->f = this->a_re->fake_stream_it(fss, rsr);

  C_INFO("Connected");
}

  void Https_client_out::disconnect() {
    Link::disconnect();
    mbedtls_ssl_close_notify( &this->ssl );

    if (this->f != nullptr) {
      delete this->f;
      this->f = nullptr;
    }
  }

// Get and set /////////////////////////////////////////////////////////////

CompoMe::String Https_client_out::get_addr() const { return this->addr; }

void Https_client_out::set_addr(const CompoMe::String p_addr) {
  this->addr = p_addr;
}

CompoMe::String &Https_client_out::a_addr() { return this->addr; }
i32 Https_client_out::get_port() const { return this->port; }

void Https_client_out::set_port(const i32 p_port) { this->port = p_port; }

i32 &Https_client_out::a_port() { return this->port; }
CompoMe::String Https_client_out::get_to() const { return this->to; }

void Https_client_out::set_to(const CompoMe::String p_to) { this->to = p_to; }

CompoMe::String &Https_client_out::a_to() { return this->to; }
CompoMe::String Https_client_out::get_ca_cert_file() const {
  return this->ca_cert_file;
}

void Https_client_out::set_ca_cert_file(const CompoMe::String p_ca_cert_file) {
  this->ca_cert_file = p_ca_cert_file;
}

CompoMe::String &Https_client_out::a_ca_cert_file() {
  return this->ca_cert_file;
}
namespace Https_client_out_ns {
// stream
Return_string_stream_recv::Return_string_stream_recv(Https_client_out &p_l)
    : CompoMe::Return_stream_recv(), a_l(p_l) {}

void Return_string_stream_recv::pull() {
  char l_buffer[1024 + 2];
  auto e = this->a_l.recv(l_buffer, 1024);
  if (e == -1) {
    C_ERROR_TAG("http,client", "Receive error");
    this->a_l.disconnect();
    return;
  }

  if (e == 0) {
    C_ERROR_TAG("http,client", "Socket close");
    this->a_l.disconnect();
    return;
  }

  atomizes::HTTPMessageParser parser;
  atomizes::HTTPMessage reponse;
  parser.Parse(&reponse, l_buffer);
  C_DEBUG_TAG("http,client,recv", "answer: ", reponse.GetMessageBody());
  auto mb = reponse.GetMessageBody();
  std::string str(mb.begin(),mb.end());
  this->a_ss.str(str+" ");
}

void Return_string_stream_recv::end() { this->a_ss.str(""); }

Function_string_stream_send::Function_string_stream_send(Https_client_out &p_l)
    : a_l(p_l) {}

void Function_string_stream_send::start() {
  this->a_ss.str("");
}

void Function_string_stream_send::send() {
  C_DEBUG_TAG("http,client,send", "call: ", this->a_ss.str());

  atomizes::HTTPMessage request;

{
  std::stringstream path;
  path << "/" << this->a_l.get_to().str;

  std::stringstream host;
  host  << this->a_l.get_addr().str<<":"<<this->a_l.get_port();

  request.SetMethod(atomizes::MessageMethod::POST)
    .SetPath(path.str())
    .SetHeader("User-Agent", "Test Agent")
    .SetHeader("Connection", "keep-alive")
    .SetHeader("Host", host.str())
    .SetMessageBody(this->a_ss.str());

}

 std::string req_s = request.ToString();
 C_INFO(req_s);
  auto r = this->a_l.send(req_s.c_str(), req_s.size());
  if (r == -1) {
    C_ERROR_TAG("http,client,send", "Send Error : ", strerror(errno));
    this->a_l.disconnect();
    throw "connection Error";
  }
}
}
} // namespace Posix

} // namespace CompoMe
