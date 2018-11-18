%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
% This is my first crack as using erlang bit syntax.  I
% engaged in this as a learning experience.  I figured pcap
% files are a worthwhile exercise. 
%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-module(pcap).

-export([pcap_create/1, each_record/2, parse/1]).

-define(PCAP_MAGIC_NATIVE, 16#a1b2c3d4).
-define(PCAP_MAGIC_SWAPPED, 16#d4c3b2a1).

-define(PCAP_HEADER_NATIVE, 
	?PCAP_MAGIC_NATIVE:32/integer,
	Major:16/integer, Minor:16/integer, Timezone:32/integer, Sigfigs:32/integer,
	Snaplen:32/integer, Network:32/integer).
	
-define(PCAP_HEADER_SWAPPED, 
	Network:32/unsigned-integer, Snaplen:32/unsigned-integer, Sigfigs:32/unsigned-integer, 
	Timezone:32/unsigned-integer, Minor:16/unsigned-integer, Major:16/unsigned-integer, 
	?PCAP_MAGIC_NATIVE:32).
	
-define(PCAP_HEADER_CONST, major=Major, minor=Minor, timezone=Timezone, sigfigs=Sigfigs, snaplen=Snaplen, network=Network ).
-define(IP_VERSION, 4).
-define(IP_MIN_HDR_LEN, 5).

-record(ip_packet, { src, dst, proto, payload }).
-record(header, { major = 0, minor = 0, timezone = 0, sigfigs = 0, snaplen = 0, network = 0 }).
-record(pcap, { swapped = false, file = false, filename = "", header = false }).
-record(record, { header = false, frame = false } ).
-record(record_header, { ts_sec = 0, ts_usec = 0, incl_len = 0, orig_len = 0 } ).
-record(frame, { src, dst, type, packet}).

pcap_create(Filename) ->
	{ok, IO} = file:open(Filename, [read,binary]),
	Swappage = determine_swappage(IO),
	{ok, Header} = read_header(IO, Swappage),
	
	#pcap{ file = IO, filename = Filename, swapped = Swappage, header = Header }.

each_record(Fun, Pcap) -> 
	case read_record(Pcap) of
		{error, Reason} -> throw({ error, Reason });
		eof -> false;
		{ok, Record} -> apply(Fun, [Record]), each_record(Fun, Pcap)
	end.

pcap_read(Pcap,Size) ->
	case file:read(Pcap#pcap.file, Size) of
		{ok, Data} -> 
			case Pcap#pcap.swapped of
				true -> {ok, util:swap(Data)};
				false -> { ok, Data }
			end;
		{error, Reason} -> {error, Reason};
		eof -> eof
	end.


extract_ip_packet(Data) ->
	case Data of
		<<?IP_VERSION:4, HLen:4, _SrvcType:8, _TotLen:16, _ID:16, _Flgs:3, _FragOff:13,_TTL:8, 
				Proto:8, _HdrChkSum:16, SrcIP:4/binary, DestIP:4/binary, RestDgram/binary>> -> 
			OptsLen = 4*(HLen - ?IP_MIN_HDR_LEN),
			DgramPayload = util:extract_binary(RestDgram, OptsLen+1, (size(RestDgram) - OptsLen)),
			
			case Proto of
				16#11 -> 
					Payload = udp:parse(DgramPayload),
					#ip_packet{ src = util:extract_ip(SrcIP), dst = util:extract_ip(DestIP), proto = Proto, payload = Payload };
				16#06 -> io:format("TCP Packets not yet supported", [ ]);
				true -> io:format("unknown packet type: ~w~n", [ Proto ])
			end;
		true -> false
	end.

read_record(Pcap) ->
	case pcap_read(Pcap, 16) of
		{ok, <<Ilen:32/integer, Olen:32/integer, Usec:32/integer, Sec:32/integer>>} -> 
			Header = #record_header{ ts_sec = Sec, ts_usec = Usec, incl_len = Ilen, orig_len = Olen },
			{ok, Data} = file:read(Pcap#pcap.file, Ilen),
			<<Type:16>> = util:extract_binary(Data, 13, 14),
			Frame = #frame{
				src = util:extract_mac(util:extract_binary(Data,1,6)),
				dst = util:extract_mac(util:extract_binary(Data,7,12)),
				type = Type,
				packet = extract_ip_packet(util:extract_binary(Data, 15, Ilen))
			},
		
			{ok, #record{ header = Header, frame = Frame }};
		{error, Reason} -> { error, Reason };
		eof -> eof
	end.

read_header(IO, Swapped) -> 
	Header = case file:read(IO,24) of
		{ok,Data} -> Data;
		{error, badarg} -> throw({ badarg, "IO must be an io handle" });
		eof -> eof
	end,
	
	case Swapped of
		true -> 
			<<?PCAP_HEADER_SWAPPED>> = util:swap( Header ),
			{ok,#header{ ?PCAP_HEADER_CONST }};
		false -> 
			io:format("native ~w~n", [ Header ]),
			{error, no_native_yet};
		error -> throw({ badarg, "Swapped must be tue or false" })
	end.


determine_swappage(File) ->
	file:position(File,0),
	{ok, <<Magic:32/integer>>} = file:read(File,4),
	file:position(File,0),
	
	case Magic of
		?PCAP_MAGIC_NATIVE -> false;
		?PCAP_MAGIC_SWAPPED -> true;
		true -> error
	end.

parse( File ) -> 
	Pcap = pcap_create(File),
	each_record(
		fun(Arg) -> 
			io:format("each_record:~n~p~n~n", [ Arg ] )
		end, 
		Pcap).
	

