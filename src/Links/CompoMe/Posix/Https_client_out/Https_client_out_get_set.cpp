#include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"

namespace CompoMe {

namespace Posix {

//============================= addr =============================
CompoMe::String Https_client_out::get_addr() const { return this->addr; }

void Https_client_out::set_addr(const CompoMe::String p_addr) {
  this->addr = p_addr;
}

CompoMe::String &Https_client_out::a_addr() { return this->addr; }
//--------------------------------------------------------------------------
//============================= port =============================
i32 Https_client_out::get_port() const { return this->port; }

void Https_client_out::set_port(const i32 p_port) { this->port = p_port; }

i32 &Https_client_out::a_port() { return this->port; }
//--------------------------------------------------------------------------
//============================= to =============================
CompoMe::String Https_client_out::get_to() const { return this->to; }

void Https_client_out::set_to(const CompoMe::String p_to) { this->to = p_to; }

CompoMe::String &Https_client_out::a_to() { return this->to; }
//--------------------------------------------------------------------------
//============================= ca_cert_file =============================
CompoMe::String Https_client_out::get_ca_cert_file() const {
  return this->ca_cert_file;
}

void Https_client_out::set_ca_cert_file(const CompoMe::String p_ca_cert_file) {
  this->ca_cert_file = p_ca_cert_file;
}

CompoMe::String &Https_client_out::a_ca_cert_file() {
  return this->ca_cert_file;
}
//--------------------------------------------------------------------------

// Get Port /////////////////////////////////////////////////////////////

CompoMe::Stream::out &Https_client_out::get_main() { return this->main; }
CompoMe::Stream::map_out &Https_client_out::get_many() { return this->many; }

} // namespace Posix

} // namespace CompoMe
