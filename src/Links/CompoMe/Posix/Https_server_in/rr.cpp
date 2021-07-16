#include "Links/CompoMe/Posix/Https_server_in/Https_server_in.hpp"

#include "Interfaces/Interface.hpp"

namespace CompoMe {

namespace Posix {

Https_server_in::Https_server_in() : CompoMe::Link(), main(), many() {
  this->main.set_link(*this);
  this->many.set_link(*this);
}

Https_server_in::~Https_server_in() {}

void Https_server_in::step() { Link::step(); }

void Https_server_in::main_connect() { Link::main_connect(); }

void Https_server_in::main_disconnect() { Link::main_disconnect(); }

// one connect
void Https_server_in::one_connect(CompoMe::Require_helper &p_r,
                                  CompoMe::String p_key) {}

void Https_server_in::one_connect(CompoMe::Interface &p_i,
                                  CompoMe::String p_key) {}

// one disconnect
void Https_server_in::one_disconnect(CompoMe::Require_helper &p_r,
                                     CompoMe::String p_key) {}

void Https_server_in::one_disconnect(CompoMe::Interface &p_i,
                                     CompoMe::String p_key) {}

} // namespace Posix

} // namespace CompoMe
