import qualified Data.ByteString as BS
import Data.Word
import Data.Bits
import Data.List (intercalate)
import System.Environment (getArgs)
import System.IO (hPutStrLn, stderr)

type Pos = Int

readU8 :: BS.ByteString -> Pos -> (Int, Pos)
readU8 bs p = (fromIntegral (BS.index bs p), p + 1)

readU16 :: BS.ByteString -> Pos -> (Int, Pos)
readU16 bs p =
    let lo = fromIntegral (BS.index bs p)
        hi = fromIntegral (BS.index bs (p+1))
    in (lo .|. (hi `shiftL` 8), p + 2)

readU32 :: BS.ByteString -> Pos -> (Int, Pos)
readU32 bs p =
    let b0 = fromIntegral (BS.index bs p)
        b1 = fromIntegral (BS.index bs (p+1))
        b2 = fromIntegral (BS.index bs (p+2))
        b3 = fromIntegral (BS.index bs (p+3))
    in (b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24), p + 4)

readStr :: BS.ByteString -> Pos -> (String, Pos)
readStr bs p =
    let (len, p1) = readU8 bs p
        s = map (toEnum . fromIntegral) $ BS.unpack $ BS.take len (BS.drop p1 bs)
    in (s, p1 + len)

readVarint :: BS.ByteString -> Pos -> (Int, Pos)
readVarint bs = go 0 0
  where
    go result shift p =
        let b = fromIntegral (BS.index bs p)
            result' = result .|. ((b .&. 0x7F) `shiftL` shift)
        in if b .&. 0x80 == 0
           then (result', p + 1)
           else go result' (shift + 7) (p + 1)

data Feed = Feed
    { feedName :: String
    , feedBaseScore :: Int
    , feedConfidence :: Int
    , feedFlagsMask :: Int
    , feedCatsMask :: Int
    , feedIPv4Starts :: [Int]
    , feedIPv4Ends :: [Int]
    , feedFlags :: [String]
    , feedCats :: [String]
    }

readStrings :: BS.ByteString -> Pos -> Int -> ([String], Pos)
readStrings _ p 0 = ([], p)
readStrings bs p n =
    let (s, p') = readStr bs p
        (rest, p'') = readStrings bs p' (n-1)
    in (s : rest, p'')

readRanges :: BS.ByteString -> Pos -> Int -> Int -> [Int] -> [Int] -> ([Int], [Int], Pos)
readRanges _ p 0 _ v4s v4e = (reverse v4s, reverse v4e, p)
readRanges bs p n cur v4s v4e =
    let (delta, p1) = readVarint bs p
        start = cur + delta
        (size, p2) = readVarint bs p1
        end' = start + size
    in if end' <= 0xFFFFFFFF
       then readRanges bs p2 (n-1) start (start:v4s) (end':v4e)
       else readRanges bs p2 (n-1) start v4s v4e

decodeMask :: [String] -> Int -> [String]
decodeMask table mask =
    [table !! i | i <- [0..length table - 1], mask .&. (1 `shiftL` i) /= 0]

load :: FilePath -> IO [Feed]
load path = do
    bs <- BS.readFile path
    let p0 = 4
        (_, p1) = readU8 bs p0
        (_, p2) = readU32 bs p1
        (fc, p3) = readU8 bs p2
        (flagTable, p4) = readStrings bs p3 fc
        (cc, p5) = readU8 bs p4
        (catTable, p6) = readStrings bs p5 cc
        (feedCount, p7) = readU16 bs p6
    return $ fst $ foldl (\(acc, p) _ ->
        let (name, pa) = readStr bs p
            (bsc, pb) = readU8 bs pa
            (co, pc) = readU8 bs pb
            (fm, pd) = readU32 bs pc
            (cm, pe) = readU8 bs pd
            (rc, pf) = readU32 bs pe
            (v4s, v4e, pg) = readRanges bs pf rc 0 [] []
            feed = Feed name bsc co fm cm v4s v4e
                       (decodeMask flagTable fm)
                       (decodeMask catTable cm)
        in (acc ++ [feed], pg)) ([], p7) [1..feedCount]

bisectRight :: [Int] -> Int -> Int
bisectRight arr target = go 0 (length arr)
  where
    go lo hi | lo >= hi = lo
             | otherwise =
        let mid = lo + (hi - lo) `div` 2
        in if arr !! mid <= target then go (mid + 1) hi
           else go lo mid

parseIPv4 :: String -> Maybe Int
parseIPv4 s = case map read (splitOn '.' s) of
    [a,b,c,d] | all (\x -> x >= 0 && x <= 255) [a,b,c,d] ->
        Just $ (a `shiftL` 24) .|. (b `shiftL` 16) .|. (c `shiftL` 8) .|. d
    _ -> Nothing

splitOn :: Char -> String -> [String]
splitOn _ [] = [""]
splitOn c (x:xs)
    | c == x    = "" : splitOn c xs
    | otherwise = let (h:t) = splitOn c xs in (x:h) : t

formatMatch :: Feed -> String
formatMatch f =
    let score = fromIntegral (feedBaseScore f) / 200.0
              * fromIntegral (feedConfidence f) / 200.0 :: Double
        parts = [feedName f, "score=" ++ showFFloat2 score]
             ++ (if null (feedFlags f) then []
                 else ["flags=" ++ intercalate "," (feedFlags f)])
             ++ (if null (feedCats f) then []
                 else ["cats=" ++ intercalate "," (feedCats f)])
    in intercalate " | " parts

showFFloat2 :: Double -> String
showFFloat2 x = let s = show (fromIntegral (round (x * 100)) / 100.0 :: Double)
                in s

main :: IO ()
main = do
    args <- getArgs
    if null args
      then hPutStrLn stderr "Usage: lookup <ip> [<ip> ...]"
      else do
        feeds <- load "blocklist.bin"
        mapM_ (lookupIP feeds) args

lookupIP :: [Feed] -> String -> IO ()
lookupIP feeds ip = case parseIPv4 ip of
    Nothing -> putStrLn $ ip ++ ": invalid IP"
    Just target -> do
        let matches = filter (\f ->
                let idx = bisectRight (feedIPv4Starts f) target - 1
                in idx >= 0 && target <= feedIPv4Ends f !! idx
                ) feeds
        if null matches
          then putStrLn $ ip ++ ": no matches"
          else mapM_ (\f -> putStrLn $ ip ++ ": " ++ formatMatch f) matches
