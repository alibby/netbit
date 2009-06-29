-module(util).

-export([extract_ip/1, swap/1, extract_binary/3, extract_mac/1]).

-define(MAC_ADDR_FORMAT, "~.16B:~.16B:~.16B:~.16B:~.16B:~.16B").
-define(IP_ADDR_FORMAT, "~.10B.~.10B.~.10B.~.10B").


extract_ip(Data) ->
	<<A/integer, B/integer, C/integer, D/integer>> = Data,
	io_lib:format(?IP_ADDR_FORMAT, [A,B,C,D]).

extract_mac(Data) -> io_lib:format(?MAC_ADDR_FORMAT, binary_to_list(Data)).
swap(Data) -> list_to_binary( lists:reverse( binary_to_list( Data ) ) ).
extract_binary(Bin, Start, End) -> list_to_binary(binary_to_list(Bin, Start, End)).
