/* /\* Https_client_out.i *\/ */

%module Https_client_out;
%include <std_string.i>

%include "Interfaces/Interface.i"


%include "Links/Link.i"






%include "Types/CompoMe/String.i"



%include "Types/i32.i"




%module Https_client_out
%{
#include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"
%}

%include "Links/CompoMe/Posix/Https_client_out/Https_client_out.hpp"