#include "Links/CompoMe/Posix/Https_server_in/Https_server_in.hpp"

namespace CompoMe {

namespace Posix {

//============================= addr =============================
CompoMe::String Https_server_in::get_addr() const { return this->addr; }

void Https_server_in::set_addr(const CompoMe::String p_addr) {
  this->addr = p_addr;
}

CompoMe::String &Https_server_in::a_addr() { return this->addr; }
//--------------------------------------------------------------------------
//============================= port =============================
i32 Https_server_in::get_port() const { return this->port; }

void Https_server_in::set_port(const i32 p_port) { this->port = p_port; }

i32 &Https_server_in::a_port() { return this->port; }
//--------------------------------------------------------------------------
//============================= max_client =============================
ui32 Https_server_in::get_max_client() const { return this->max_client; }

void Https_server_in::set_max_client(const ui32 p_max_client) {
  this->max_client = p_max_client;
}

ui32 &Https_server_in::a_max_client() { return this->max_client; }
//--------------------------------------------------------------------------
//============================= max_request_size =============================
ui32 Https_server_in::get_max_request_size() const {
  return this->max_request_size;
}

void Https_server_in::set_max_request_size(const ui32 p_max_request_size) {
  this->max_request_size = p_max_request_size;
}

ui32 &Https_server_in::a_max_request_size() { return this->max_request_size; }
//--------------------------------------------------------------------------
//============================= cert_file =============================
CompoMe::String Https_server_in::get_cert_file() const {
  return this->cert_file;
}

void Https_server_in::set_cert_file(const CompoMe::String p_cert_file) {
  this->cert_file = p_cert_file;
}

CompoMe::String &Https_server_in::a_cert_file() { return this->cert_file; }
//--------------------------------------------------------------------------
//============================= key_file =============================
CompoMe::String Https_server_in::get_key_file() const { return this->key_file; }

void Https_server_in::set_key_file(const CompoMe::String p_key_file) {
  this->key_file = p_key_file;
}

CompoMe::String &Https_server_in::a_key_file() { return this->key_file; }
//--------------------------------------------------------------------------

// Get Port /////////////////////////////////////////////////////////////

CompoMe::Stream::in &Https_server_in::get_main() { return this->main; }
CompoMe::Stream::map_in &Https_server_in::get_many() { return this->many; }

} // namespace Posix

} // namespace CompoMe
