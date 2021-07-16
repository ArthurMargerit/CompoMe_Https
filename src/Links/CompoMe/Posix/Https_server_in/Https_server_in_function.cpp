#include "CompoMe/Log.hpp"
#include "Links/CompoMe/Posix/Https_server_in/Https_server_in.hpp"

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

bool Https_server_in::accept() {
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

bool Https_server_in::write(int i, const std::string &r) {
  int ret = mbedtls_ssl_write(&this->ssl[i], (const unsigned char *)r.c_str(),
                              r.length());

  if (ret > 0) {
    return true;
  } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
    C_ERROR_TAG("https,write", "on fd=", this->fds[i].fd, " ssl conn reset");
    return false;
  } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
             ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    C_ERROR_TAG("https,write", "on fd=", this->fds[i].fd,
                " ret != (SSL_WANT_READ&SSL_WANT_WRITE)");
    return false;
  }

  return false;
}

bool Https_server_in::read(int i) {
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

} // namespace Posix

} // namespace CompoMe
