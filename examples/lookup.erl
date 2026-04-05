-module(lookup).

-export([
    load/1,
    lookup/2
]).

-define(IPV4_MAX, 16#FFFFFFFF).

load(File) ->
    {ok, Data} = file:read_file(File),
    <<"IPBL", 2:8, _Timestamp:32/little, Rest/binary>> = Data,
    {Flags, Rest2} = read_string_table(Rest),
    {Cats,  Rest3} = read_string_table(Rest2),
    <<FeedCount:16/little, Rest4/binary>> = Rest3,
    {Feeds, _} = read_feeds(Rest4, FeedCount, Flags, Cats, []),
    Feeds.

lookup(Feeds, IpBin) ->
    case parse_ip(IpBin) of
        {ok, v4, Target} ->
            do_lookup(Feeds, IpBin, Target, v4);
        {ok, v6, Target} ->
            do_lookup(Feeds, IpBin, Target, v6);
        Error ->
            Error
    end.

% internals

read_string_table(<<Count:8, Rest/binary>>) ->
    read_strings(Rest, Count, 0, #{}).

read_strings(Rest, 0, _, Acc) ->
    {Acc, Rest};
read_strings(<<Len:8, Name:Len/binary, Rest/binary>>, N, I, Acc) ->
    read_strings(Rest, N - 1, I + 1, Acc#{I => Name}).

bits_to_list(Mask, Table) ->
    maps:fold(fun(I, Name, Acc) ->
        case Mask band (1 bsl I) of
            0 ->
                Acc;
            _ ->
                [Name | Acc]
        end
    end, [], Table).

read_feeds(_, 0, _, _, Acc) ->
    {Acc, <<>>};
read_feeds(<<NLen:8, Name:NLen/binary, BS:8, CO:8, FM:32/little, CM:8, RC:32/little, Rest/binary>>, N, Flags, Cats, Acc) ->
    {V4S, V4E, V6S, V6E, Rest2} = read_ranges(Rest, RC, 0, [], [], [], []),
    Feed = #{
        name => Name,
        base_score => BS,
        confidence => CO,
        score => (BS / 200.0) * (CO / 200.0),
        flags => bits_to_list(FM, Flags),
        categories => bits_to_list(CM, Cats),
        v4s => list_to_tuple(lists:reverse(V4S)),
        v4e => list_to_tuple(lists:reverse(V4E)),
        v6s => list_to_tuple(lists:reverse(V6S)),
        v6e => list_to_tuple(lists:reverse(V6E))
    },
    read_feeds(Rest2, N - 1, Flags, Cats, [Feed | Acc]).

read_ranges(Rest, 0, _, V4S, V4E, V6S, V6E) ->
    {V4S, V4E, V6S, V6E, Rest};
read_ranges(Bin, N, Cur, V4S, V4E, V6S, V6E) ->
    {Delta, R1} = decode_varint(Bin),
    Start = Cur + Delta,
    {Size, R2} = decode_varint(R1),
    End = Start + Size,
    case End =< ?IPV4_MAX of
        true  ->
            read_ranges(R2, N-1, Start, [Start|V4S], [End|V4E], V6S, V6E);
        _ ->
            read_ranges(R2, N-1, Start, V4S, V4E, [Start|V6S], [End|V6E])
    end.

decode_varint(Bin) ->
    decode_varint(Bin, 0, 0).

decode_varint(<<B:8, Rest/binary>>, Result, Shift) ->
    Value = Result bor ((B band 16#7F) bsl Shift),
    case B band 16#80 of
        0 ->
            {Value, Rest};
        _ ->
            decode_varint(Rest, Value, Shift + 7)
    end.

do_lookup(Feeds, _IpBin, Target, Version) ->
    case [F || F <- Feeds, contains(F, Target, Version)] of
        [] ->
            no_match;
        Matches ->
            Fun = fun(#{name := Name, score := Score, flags := Fl, categories := Ca}) ->
                #{name => Name, score => Score, flags => Fl, categories => Ca}
            end,
            lists:map(Fun, Matches)
    end.

contains(#{v4s := S, v4e := E}, Target, v4) ->
    in_range(S, E, Target);
contains(#{v6s := S, v6e := E}, Target, v6) ->
    in_range(S, E, Target);
contains(_, _, _) ->
    false.

in_range(Starts, Ends, Target) ->
    Idx = bisect_right(Starts, Target, 1, tuple_size(Starts)),
    Idx > 0 andalso Target =< element(Idx, Ends).

bisect_right(_, _, Lo, Hi) when Lo > Hi ->
    Lo - 1;
bisect_right(Arr, Target, Lo, Hi) ->
    Mid = Lo + (Hi - Lo) div 2,
    case element(Mid, Arr) =< Target of
        true  ->
            bisect_right(Arr, Target, Mid + 1, Hi);
        false ->
            bisect_right(Arr, Target, Lo, Mid - 1)
    end.

parse_ip(IPBin) ->
    case inet:parse_address(binary_to_list(IPBin)) of
        {ok, {A, B, C, D}} ->
            {ok, v4, (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D};
        {ok, {A, B, C, D, E, F, G, H}} ->
            {ok, v6, (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H};
        _ ->
            {error, invalid_ip}
    end.
