#include "Links/CompoMe/Posix/Https_server_map_in/Https_server_map_in.hpp"
#include "CompoMe/Log.hpp"
#include "CompoMe/Tools/Http/Call.hpp"
#include "Interfaces/Interface.hpp"

namespace CompoMe {

namespace Posix {

namespace {
#if defined(COMPOME_LOG) && COMPOME_LOG
const char *mbedtls_error_wrp(int ret, char *buf = nullptr, size_t buflen = 0) {
  static char l_buff[100];
  if (buf == nullptr) {
    buf = l_buff;
    buflen = 100;
  }
  mbedtls_strerror(ret, buf, buflen);
  return buf;
}
#endif
} // namespace

Https_server_map_in::Https_server_map_in() : CompoMe::Link() {
  mbedtls_ssl_config_init(&this->conf);
  mbedtls_x509_crt_init(&this->srvcert);
  mbedtls_pk_init(&this->pkey);
  mbedtls_entropy_init(&this->entropy);
  mbedtls_ctr_drbg_init(&this->ctr_drbg);
}

Https_server_map_in::~Https_server_map_in() {
  mbedtls_x509_crt_free(&this->srvcert);
  mbedtls_pk_free(&this->pkey);
  mbedtls_ssl_config_free(&this->conf);
  mbedtls_ctr_drbg_free(&this->ctr_drbg);
  mbedtls_entropy_free(&this->entropy);
}

bool Https_server_map_in::accept() {
  mbedtls_net_init(&this->ssl_fds[this->i_fds]);

  int ret = mbedtls_net_accept(&this->ssl_fds[0], &this->ssl_fds[this->i_fds],
                               NULL, 0, NULL);

  if (ret != 0) {
    C_ERROR_TAG("https,accept", "accept on fd=", this->ssl_fds[this->i_fds].fd,
                " ", mbedtls_error_wrp(ret));
    return false;
  }

  this->fds[this->i_fds].fd = this->ssl_fds[this->i_fds].fd;
  this->fds[this->i_fds].events = POLLIN | POLLHUP | POLLERR;
  this->fds[this->i_fds].revents = 0;
  mbedtls_ssl_init(&this->ssl[this->i_fds]);
  ret = mbedtls_ssl_setup(&this->ssl[this->i_fds], &this->conf);
  if (ret != 0) {
    C_ERROR_TAG("https,stuff", "ssl setup - ", mbedtls_error_wrp(ret));
    return false;
  }
  mbedtls_ssl_set_bio(&this->ssl[this->i_fds], &this->ssl_fds[this->i_fds],
                      mbedtls_net_send, mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(&this->ssl[this->i_fds])) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      C_ERROR_TAG("https,accept,handshake", "on fd=", this->fds[this->i_fds].fd,
                  " ", mbedtls_error_wrp(ret));
      return false;
    }
  }

  //  this->fds[0].revents = this->fds[0].revents - POLLIN; // remove it
  C_INFO_TAG("https,server,recv", "new client fd=", this->fds[this->i_fds].fd);

  this->i_fds++;
  return true;
}

void Https_server_map_in::step() {
  Link::step();

  int ret;
  ret = poll(this->fds, this->i_fds, 0);
  if (ret == 0) {
    // C_DEBUG("Timeout Poll() on socket");
    return;
  } else if (ret == -1) {
    C_ERROR("in Poll() on socket ", strerror(errno));
    return;
  }

  int len;
  // socket message
  // if it's the listening_socket manage the new connection
  if (this->fds[0].revents & POLLERR) {
    C_ERROR_TAG("Https,Poll", "in Poll() for fd=", this->fds[0].fd,
                " error:", strerror(errno));
  }

  if (this->fds[0].revents & POLLIN) {
    this->accept();
  }

  if (this->fds[0].revents & POLLHUP) {
    this->disconnect();
  }

  for (int i = 1; i < this->i_fds; i++) {
    if (this->fds[i].revents & POLLERR) {
      C_ERROR_TAG("Https,Poll", "in Poll() for fd=", this->fds[i].fd,
                  " error:", strerror(errno));
    }

    if (this->fds[i].revents & POLLIN) {
      if (!this->read(i)) {
        this->disconnect(i);
        i--;
        continue;
      }

      C_INFO_TAG("https,recv", "mess fd=", this->fds[i].fd,
                 " recv:" , this->buf);
      auto r = CompoMe::Tools::Http::call(this->get_map_of_caller_stream(),
                                          (char *)this->buf);
      C_INFO_TAG("https,send", "mess fd=", this->fds[i].fd,
                 " send:" , r.second);
      this->write(i,r.second);

    }

    if (this->fds[i].revents & POLLHUP) {
      this->disconnect(i);
      i--;
      continue;
    }
  }
}

bool Https_server_map_in::write(int i, const std::string& r) {
  int ret = mbedtls_ssl_write(&this->ssl[i],
                              (const unsigned char *)r.c_str(),
                              r.length());

  if(ret > 0 ){
  return true;
   }else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
      C_ERROR_TAG("https,write", "on fd=", this->fds[i].fd,
                  " ssl conn reset");
      return false;
    } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      C_ERROR_TAG("https,write", "on fd=", this->fds[i].fd,
                  " ret != (SSL_WANT_READ&SSL_WANT_WRITE)");
      return false;
    }

    return false;
}

bool Https_server_map_in::read(int i) {
  int ret =
      mbedtls_ssl_read(&this->ssl[i], this->buf, this->get_max_request_size());

  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    C_ERROR_TAG("https,read", "on fd=", this->fds[i].fd,
                " ret != of SSL_WANT_WRITE or SSL_WANT_READ");
    return false;
  }

  if (ret <= 0) {
    switch (ret) {
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      C_INFO_TAG("https,read", "on fd=", this->fds[i].fd, " ssl peer close");
      return false;

    case MBEDTLS_ERR_NET_CONN_RESET:
      C_ERROR_TAG("https,read", "on fd=", this->fds[i].fd, " ssl conn reset");
      return false;

    default:
      return false;
    }
  }

  this->buf[ret] = '\0';
  return true;
}

void Https_server_map_in::disconnect(int i) {
  C_INFO_TAG("https,client", "client out fd=", this->fds[i].fd);
  mbedtls_net_free(&this->ssl_fds[i]);
  mbedtls_ssl_free(&this->ssl[i]);

  // if it's the lastone
  if (i != this->i_fds - 1) {
  // swap it with the lastone
  this->ssl_fds[i] = this->ssl_fds[this->i_fds - 1];
  this->ssl[i] = this->ssl[this->i_fds - 1];
  this->fds[i].fd = this->fds[this->i_fds - 1].fd;
  this->fds[i].events = this->fds[this->i_fds - 1].events;
  this->fds[i].revents = this->fds[this->i_fds - 1].revents;
  }
  
  this->i_fds--;
}

void Https_server_map_in::connect() {
  Link::connect();
  int ret;

  // 1. Load the certificates and private RSA key
  ret =
      mbedtls_x509_crt_parse_file(&srvcert, this->get_cert_file().str.c_str());
  if (ret != 0) {
    C_ERROR_TAG("https,cert,file", "Cert file is not valid - ",
                mbedtls_error_wrp(ret));
    return;
  }

  ret = mbedtls_pk_parse_keyfile(&pkey, this->get_key_file().str.c_str(), NULL);
  if (ret != 0) {
    C_ERROR_TAG("https,key,file", "Key file is not valid - ",
                mbedtls_error_wrp(ret));
    return;
  }
  /*************************************************************************************/

  // 2. Setup the listening TCP socket
  std::stringstream ss;
  ss << this->get_port();
  mbedtls_net_context listen_fd;
  ret = mbedtls_net_bind(&listen_fd, this->get_addr().str.c_str(),
                         ss.str().c_str(), MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    C_ERROR_TAG("https,bind", "bind failed - ", mbedtls_error_wrp(ret));
    return;
  }
  /*************************************************************************************/

  // 3. Seed the RNG
  const char *pers = "ssl_server";
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    C_ERROR_TAG("https,seed", "init seed - ", mbedtls_error_wrp(ret));
    return;
  }
  /*************************************************************************************/

  // 4. Setup stuff
  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    C_ERROR_TAG("https,stuff", "ssl config default - ", mbedtls_error_wrp(ret));
    return;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
  ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
  if (ret != 0) {
    C_ERROR_TAG("https,stuff", "ssl config cert - ", mbedtls_error_wrp(ret));
    return;
  }

  this->buf =
      (unsigned char *)malloc(this->get_max_request_size() * sizeof(*buf) + 1);
  if (this->buf == nullptr) {
    C_ERROR_TAG("https,malloc", "Allocation failed for buffer size_buffer=",
                this->get_max_request_size());
  }

  {
    // +1 due to listening socket in this->fds[0]
    this->fds = (struct pollfd *)malloc((this->get_max_client() + 1) *
                                        sizeof(*this->fds));
    this->ssl_fds = (mbedtls_net_context *)malloc((this->get_max_client() + 1) *
                                                  sizeof(*this->ssl_fds));

    this->ssl = (mbedtls_ssl_context *)malloc((this->get_max_client() + 1) *
                                              sizeof(*this->ssl));
    if (this->fds == nullptr) {
      C_ERROR_TAG("https,malloc", "Malloc failed for fds size asked is ",
                  (this->get_max_client() + 1) * sizeof(*this->fds));
      this->disconnect();
      return;
    }

    this->fds[0].fd = listen_fd.fd;
    this->ssl_fds[0] = listen_fd;
    this->ssl[0] = {};
    this->fds[0].events = POLLIN | POLLERR | POLLHUP;
    this->fds[0].revents = 0;
    this->i_fds = 1; // listening socket
  }
}

void Https_server_map_in::disconnect() {
  Link::disconnect();

  if (this->fds != nullptr &&
      this->fds[0].fd != -1) {
    mbedtls_net_free(&this->ssl_fds[0]);
    this->fds[0].fd = -1;
  }

  if (this->fds != nullptr) {

    for (int i = 1; i < this->i_fds; i++) {
      int ret = 0;
      while ((ret = mbedtls_ssl_close_notify(&this->ssl[i])) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
          C_ERROR_TAG("https,close", "on fd=", this->fds[i].fd,
                      " ret != (SSL_WANT_READ&SSL_WANT_WRITE)");
          return;
        }
      }

      mbedtls_net_free(&this->ssl_fds[i]);
      mbedtls_ssl_free(&this->ssl[i]);
      this->fds[i].fd = -1;
    }

    free(this->fds);
    free(this->ssl_fds);
    free(this->ssl);

    this->ssl_fds = nullptr;
    this->ssl = nullptr;
    this->fds = nullptr;
  }

  free(this->buf);
  this->buf = nullptr;
}

// Get and set /////////////////////////////////////////////////////////////

CompoMe::String Https_server_map_in::get_addr() const { return this->addr; }

void Https_server_map_in::set_addr(const CompoMe::String p_addr) {
  this->addr = p_addr;
}

CompoMe::String &Https_server_map_in::a_addr() { return this->addr; }
i32 Https_server_map_in::get_port() const { return this->port; }

void Https_server_map_in::set_port(const i32 p_port) { this->port = p_port; }

i32 &Https_server_map_in::a_port() { return this->port; }
ui32 Https_server_map_in::get_max_client() const { return this->max_client; }

void Https_server_map_in::set_max_client(const ui32 p_max_client) {
  this->max_client = p_max_client;
}

ui32 &Https_server_map_in::a_max_client() { return this->max_client; }
ui32 Https_server_map_in::get_max_request_size() const {
  return this->max_request_size;
}

void Https_server_map_in::set_max_request_size(const ui32 p_max_request_size) {
  this->max_request_size = p_max_request_size;
}

ui32 &Https_server_map_in::a_max_request_size() {
  return this->max_request_size;
}
CompoMe::String Https_server_map_in::get_cert_file() const {
  return this->cert_file;
}

void Https_server_map_in::set_cert_file(const CompoMe::String p_cert_file) {
  this->cert_file = p_cert_file;
}

CompoMe::String &Https_server_map_in::a_cert_file() { return this->cert_file; }
CompoMe::String Https_server_map_in::get_key_file() const {
  return this->key_file;
}

void Https_server_map_in::set_key_file(const CompoMe::String p_key_file) {
  this->key_file = p_key_file;
}

CompoMe::String &Https_server_map_in::a_key_file() { return this->key_file; }

} // namespace Posix

} // namespace CompoMe
