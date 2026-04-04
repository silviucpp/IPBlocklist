#!/usr/bin/env escript
-mode(compile).

main(Args) when length(Args) < 1 ->
    io:format("Usage: escript lookup.erl <ip> [<ip> ...]~n");
main(Args) ->
    {ok, Data} = file:read_file("blocklist.bin"),
    <<"IPBL", 2:8, Timestamp:32/little, Rest/binary>> = Data,
    {Flags, Rest2} = read_string_table(Rest),
    {Cats, Rest3} = read_string_table(Rest2),
    <<FeedCount:16/little, Rest4/binary>> = Rest3,
    {Feeds, _} = read_feeds(Rest4, FeedCount, Flags, Cats, []),
    lists:foreach(fun(IpStr) -> lookup(Feeds, IpStr) end, Args).

read_string_table(<<Count:8, Rest/binary>>) ->
    read_strings(Rest, Count, []).

read_strings(Rest, 0, Acc) -> {lists:reverse(Acc), Rest};
read_strings(<<Len:8, Name:Len/binary, Rest/binary>>, N, Acc) ->
    read_strings(Rest, N - 1, [binary_to_list(Name) | Acc]).

read_feeds(Rest, 0, _, _, Acc) -> {lists:reverse(Acc), Rest};
read_feeds(Bin, N, Flags, Cats, Acc) ->
    <<NLen:8, Name:NLen/binary, BS:8, CO:8,
      FM:32/little, CM:8, RC:32/little, Rest/binary>> = Bin,
    {Ranges, Rest2} = read_ranges(Rest, RC, 0, [], []),
    {V4S, V4E} = Ranges,
    MatchedFlags = [lists:nth(I+1, Flags)
        || I <- lists:seq(0, length(Flags)-1), FM band (1 bsl I) =/= 0],
    MatchedCats = [lists:nth(I+1, Cats)
        || I <- lists:seq(0, length(Cats)-1), CM band (1 bsl I) =/= 0],
    Feed = #{name => binary_to_list(Name),
             base_score => BS, confidence => CO,
             flags => MatchedFlags, categories => MatchedCats,
             v4s => list_to_tuple(lists:reverse(V4S)),
             v4e => list_to_tuple(lists:reverse(V4E))},
    read_feeds(Rest2, N - 1, Flags, Cats, [Feed | Acc]).

read_ranges(Rest, 0, _, V4S, V4E) -> {{V4S, V4E}, Rest};
read_ranges(Bin, N, Cur, V4S, V4E) ->
    {Delta, R1} = decode_varint(Bin, 0, 0),
    Start = Cur + Delta,
    {Size, R2} = decode_varint(R1, 0, 0),
    End = Start + Size,
    case End =< 16#FFFFFFFF of
        true -> read_ranges(R2, N-1, Start, [Start|V4S], [End|V4E]);
        false -> read_ranges(R2, N-1, Start, V4S, V4E)
    end.

decode_varint(<<B:8, Rest/binary>>, Result, Shift) ->
    Value = Result bor ((B band 16#7F) bsl Shift),
    case B band 16#80 of
        0 -> {Value, Rest};
        _ -> decode_varint(Rest, Value, Shift + 7)
    end.

lookup(Feeds, IpStr) ->
    case parse_ipv4(IpStr) of
        {ok, Target} ->
            Matches = [F || F <- Feeds, contains(F, Target)],
            case Matches of
                [] -> io:format("~s: no matches~n", [IpStr]);
                _ -> lists:foreach(
                    fun(F) -> print_match(IpStr, F) end, Matches)
            end;
        error ->
            io:format("~s: invalid IP~n", [IpStr])
    end.

contains(#{v4s := Starts, v4e := Ends}, Target) ->
    Idx = bisect_right(Starts, Target, 1, tuple_size(Starts)),
    Idx > 0 andalso Target =< element(Idx, Ends).

bisect_right(_, _, Lo, Hi) when Lo > Hi -> Lo - 1;
bisect_right(Arr, Target, Lo, Hi) ->
    Mid = Lo + (Hi - Lo) div 2,
    case element(Mid, Arr) =< Target of
        true -> bisect_right(Arr, Target, Mid + 1, Hi);
        false -> bisect_right(Arr, Target, Lo, Mid - 1)
    end.

parse_ipv4(Str) ->
    case inet:parse_address(Str) of
        {ok, {A, B, C, D}} -> {ok, (A bsl 24) bor (B bsl 16)
                                   bor (C bsl 8) bor D};
        _ -> error
    end.

print_match(IpStr, #{name := Name, base_score := BS,
                      confidence := CO, flags := Fl, categories := Ca}) ->
    Score = (BS / 200.0) * (CO / 200.0),
    Parts = [Name, io_lib:format("score=~.2f", [Score])]
        ++ case Fl of [] -> []; _ ->
            ["flags=" ++ string:join(Fl, ",")] end
        ++ case Ca of [] -> []; _ ->
            ["cats=" ++ string:join(Ca, ",")] end,
    io:format("~s: ~s~n", [IpStr, string:join(Parts, " | ")]).
