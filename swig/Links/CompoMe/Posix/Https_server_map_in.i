/* /\* Https_server_map_in.i *\/ */

%module Https_server_map_in;
%include <std_string.i>

%include "Interfaces/Interface.i"


%include "Links/Link.i"






%include "Types/CompoMe/String.i"



%include "Types/i32.i"



%include "Types/ui32.i"




%module Https_server_map_in
%{
#include "Links/CompoMe/Posix/Https_server_map_in/Https_server_map_in.hpp"
%}

%include "Links/CompoMe/Posix/Https_server_map_in/Https_server_map_in.hpp"