defmodule Lookup do
  def main(args) when length(args) < 1 do
    IO.puts("Usage: elixir lookup.exs <ip> [<ip> ...]")
  end

  def main(args) do
    feeds = load("blocklist.bin")
    Enum.each(args, &lookup(feeds, &1))
  end

  defp load(path) do
    data = File.read!(path)
    <<"IPBL", 2, _ts::little-32, rest::binary>> = data
    {flags, rest} = read_string_table(rest)
    {cats, rest} = read_string_table(rest)
    <<fc::little-16, rest::binary>> = rest
    {feeds, _} = read_feeds(rest, fc, flags, cats, [])
    feeds
  end

  defp read_string_table(<<count, rest::binary>>) do
    Enum.reduce(1..count, {[], rest}, fn _, {acc, r} ->
      <<len, name::binary-size(len), r2::binary>> = r
      {[name | acc], r2}
    end)
    |> then(fn {list, r} -> {Enum.reverse(list), r} end)
  end

  defp read_feeds(rest, 0, _, _, acc), do: {Enum.reverse(acc), rest}

  defp read_feeds(bin, n, flags, cats, acc) do
    <<nlen, name::binary-size(nlen), bs, co,
      fm::little-32, cm, rc::little-32, rest::binary>> = bin

    {v4s, v4e, rest} = read_ranges(rest, rc, 0, [], [])

    matched_flags = for i <- 0..(length(flags)-1),
      Bitwise.band(fm, Bitwise.bsl(1, i)) != 0,
      do: Enum.at(flags, i)

    matched_cats = for i <- 0..(length(cats)-1),
      Bitwise.band(cm, Bitwise.bsl(1, i)) != 0,
      do: Enum.at(cats, i)

    feed = %{
      name: name, bs: bs, co: co,
      flags: matched_flags, cats: matched_cats,
      v4s: :array.from_list(Enum.reverse(v4s)),
      v4e: :array.from_list(Enum.reverse(v4e))
    }

    read_feeds(rest, n - 1, flags, cats, [feed | acc])
  end

  defp read_ranges(rest, 0, _, v4s, v4e), do: {v4s, v4e, rest}

  defp read_ranges(bin, n, cur, v4s, v4e) do
    {delta, r1} = decode_varint(bin, 0, 0)
    start = cur + delta
    {size, r2} = decode_varint(r1, 0, 0)
    en = start + size

    if en <= 0xFFFFFFFF do
      read_ranges(r2, n-1, start, [start | v4s], [en | v4e])
    else
      read_ranges(r2, n-1, start, v4s, v4e)
    end
  end

  defp decode_varint(<<b, rest::binary>>, result, shift) do
    value = Bitwise.bor(result, Bitwise.bsl(Bitwise.band(b, 0x7F), shift))
    if Bitwise.band(b, 0x80) == 0 do
      {value, rest}
    else
      decode_varint(rest, value, shift + 7)
    end
  end

  defp lookup(feeds, ip_str) do
    case parse_ipv4(ip_str) do
      {:ok, target} ->
        matches = Enum.filter(feeds, &contains?(&1, target))
        if matches == [] do
          IO.puts("#{ip_str}: no matches")
        else
          Enum.each(matches, &print_match(ip_str, &1))
        end
      :error ->
        IO.puts("#{ip_str}: invalid IP")
    end
  end

  defp contains?(%{v4s: starts, v4e: ends}, target) do
    size = :array.size(starts)
    idx = bisect_right(starts, target, 0, size) - 1
    idx >= 0 and target <= :array.get(idx, ends)
  end

  defp bisect_right(_, _, lo, hi) when lo >= hi, do: lo

  defp bisect_right(arr, target, lo, hi) do
    mid = lo + div(hi - lo, 2)
    if :array.get(mid, arr) <= target do
      bisect_right(arr, target, mid + 1, hi)
    else
      bisect_right(arr, target, lo, mid)
    end
  end

  defp parse_ipv4(str) do
    case :inet.parse_address(to_charlist(str)) do
      {:ok, {a, b, c, d}} ->
        {:ok, Bitwise.bsl(a, 24) |> Bitwise.bor(Bitwise.bsl(b, 16))
              |> Bitwise.bor(Bitwise.bsl(c, 8)) |> Bitwise.bor(d)}
      _ -> :error
    end
  end

  defp print_match(ip, %{name: name, bs: bs, co: co,
                          flags: fl, cats: ca}) do
    score = bs / 200.0 * (co / 200.0)
    parts = [name, "score=#{:erlang.float_to_binary(score, decimals: 2)}"]
    parts = if fl != [], do: parts ++ ["flags=#{Enum.join(fl, ",")}"],
            else: parts
    parts = if ca != [], do: parts ++ ["cats=#{Enum.join(ca, ",")}"],
            else: parts
    IO.puts("#{ip}: #{Enum.join(parts, " | ")}")
  end
end

Lookup.main(System.argv())
