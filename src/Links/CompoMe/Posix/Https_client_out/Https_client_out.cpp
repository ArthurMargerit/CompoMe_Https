#include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"
#include "CompoMe/Log.hpp"
#include "Interfaces/Interface.hpp"
#include "Links/atomizes.hpp"
#include <cstring>

namespace CompoMe {

namespace Posix {
  const char *pers = "ssl_client1";
  
Https_client_out::Https_client_out() : CompoMe::Link(), main(), many() {
  this->main.set_link(*this);
  this->many.set_link(*this);

  int ret;
  mbedtls_net_init(&this->server_fd);
  mbedtls_ssl_init(&this->ssl);
  mbedtls_ssl_config_init(&this->conf);
  mbedtls_x509_crt_init(&this->cacert);
  mbedtls_ctr_drbg_init(&this->ctr_drbg);
  mbedtls_entropy_init(&this->entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    C_ERROR(" ! mbedtls_ctr_drbg_seed returned %d\n", ret);
  }
}

Https_client_out::~Https_client_out() {
  mbedtls_net_free(&this->server_fd);

  mbedtls_x509_crt_free(&this->cacert);
  mbedtls_ssl_free(&this->ssl);
  mbedtls_ssl_config_free(&this->conf);
  mbedtls_ctr_drbg_free(&this->ctr_drbg);
  mbedtls_entropy_free(&this->entropy);
}

void Https_client_out::step() { Link::step(); }

void Https_client_out::main_connect() {
  Link::main_connect();
  int ret = mbedtls_x509_crt_parse_file(&this->cacert,
                                        this->get_ca_cert_file().str.c_str());
  if (ret < 0) {
    C_ERROR("! mbedtls_x509_crt_parse returned %d", ret);
    return;
  }

  std::stringstream ss;
  ss << this->get_port();
  ret = mbedtls_net_connect(&this->server_fd, this->get_addr().str.c_str(),
                            ss.str().c_str(), MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    C_ERROR("! mbedtls_net_connect returned %d", ret);
    return;
  }

  ret = mbedtls_ssl_config_defaults(&this->conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    C_ERROR("! mbedtls_ssl_config_defaults returned %d", ret);
    return;
  }

  /* OPTIONAL is not optimal for security,
   * but makes interop easier in this simplified example */
  mbedtls_ssl_conf_authmode(&this->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&this->conf, &this->cacert, NULL);
  mbedtls_ssl_conf_rng(&this->conf, mbedtls_ctr_drbg_random, &this->ctr_drbg);
  ret = mbedtls_ssl_setup(&this->ssl, &this->conf);
  if (ret != 0) {
    C_ERROR("! mbedtls_ssl_setup returned %d", ret);
    return;
  }

  ret = mbedtls_ssl_set_hostname(&this->ssl, this->get_addr().str.c_str());
  if (ret != 0) {
    C_ERROR("! mbedtls_ssl_set_hostname returned %d", ret);
    return;
  }

  mbedtls_ssl_set_bio(&this->ssl, &this->server_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);

  /*
   * 4. Handshake
   */
  while ((ret = mbedtls_ssl_handshake(&this->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      C_ERROR("! mbedtls_ssl_handshake returned -0x%x", (unsigned int)-ret);
      return;
    }
  }

  /*
   * 5. Verify the server certificate
   */
  uint32_t flags;
  flags = mbedtls_ssl_get_verify_result(&this->ssl);
  if (flags != 0) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    C_WARNING(vrfy_buf);
  }

  C_INFO("Connected");
}

void Https_client_out::main_disconnect() {
  Link::main_disconnect();
  mbedtls_ssl_close_notify(&this->ssl);
}

// one connect
void Https_client_out::one_connect(CompoMe::Require_helper &p_r,
                                   CompoMe::String p_key) {
  auto &nc = this->fake_many[p_key];

  nc.fss.set_func_send([this, p_key](CompoMe::String_d &d) {
    std::stringstream path;
    path << "/"; // p_key.str;

    std::stringstream host;
    host << this->get_addr().str << ":" << this->get_port();

    atomizes::HTTPMessage request;
    request.SetMethod(atomizes::MessageMethod::POST)
        .SetPath(path.str())
        .SetHeader("User-Agent", "Test Agent")
        .SetHeader("Connection", "keep-alive")
        .SetHeader("Host", host.str())
        .SetMessageBody(d.str);

    std::string req_s = request.ToString();

    auto r = this->send(req_s.c_str(), req_s.size());
    if (r == -1) {
      C_ERROR_TAG("http,client,send", "Send Error : ", strerror(errno));
      this->main_disconnect();
      throw "connection Error";
    }

    return true;
  });

  nc.rss.set_func_recv([this](CompoMe::String_d &d) {
    char l_buffer[1024 + 2];
    auto e = this->recv(l_buffer, 1024);
    if (e == -1) {
      C_ERROR_TAG("http,client", "Receive error");
      this->main_disconnect();
      return false;
    }

    if (e == 0) {
      C_ERROR_TAG("http,client", "Socket close");
      this->main_disconnect();
      return false;
    }

    l_buffer[e] = ' ';
    l_buffer[e + 1] = '\0';

    atomizes::HTTPMessageParser parser;
    atomizes::HTTPMessage reponse;
    parser.Parse(&reponse, l_buffer);

    auto mb = reponse.GetMessageBody();
    std::string str(mb.begin(), mb.end());
    d.str = str;

    return true;
  });

  nc.f = p_r.fake_stream_it(nc.fss, nc.rss);
}

void Https_client_out::one_connect(CompoMe::Interface &p_i,
                                   CompoMe::String p_key) {}

// one disconnect
void Https_client_out::one_disconnect(CompoMe::Require_helper &p_r,
                                      CompoMe::String p_key) {}

void Https_client_out::one_disconnect(CompoMe::Interface &p_i,
                                      CompoMe::String p_key) {}

} // namespace Posix

} // namespace CompoMe
