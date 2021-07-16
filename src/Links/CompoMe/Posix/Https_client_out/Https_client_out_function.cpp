#include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"
#include "CompoMe/Log.hpp"

namespace CompoMe {

namespace Posix {

i32 Https_client_out::send(const char *buff, i32 size_buff) {

  int ret;
  while ((ret = mbedtls_ssl_write(&this->ssl, (const unsigned char *)buff,
                                  size_buff)) <= 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      C_ERROR("mbedtls_ssl_write returned %d", ret);
      return -1;
    }
  }

  return 0;
}

i32 Https_client_out::recv(char *buff, i32 size_buff) {
  int len;
  do {
    int ret =
        mbedtls_ssl_read(&this->ssl, (unsigned char *)buff, size_buff - 1);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      C_ERROR("MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY")
      return -1;
    }

    if (ret < 0) {
      C_ERROR("! mbedtls_ssl_read returned %d", ret);
      return -1;
    }

    if (ret == 0) {
      break;
    }

    len = ret;
    break;
  } while (1);

  buff[len] = '\0';
  return len;
}

} // namespace Posix

} // namespace CompoMe
