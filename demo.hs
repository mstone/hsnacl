#!/usr/bin/runhaskell
import qualified Data.ByteString.Char8 as BS
import qualified Codec.Nacl.Internal as CNI
import qualified Codec.Nacl as CN

main = do
  (pk1, sk1) <- CN.keypair
  (pk2, sk2) <- CN.keypair
  let n = BS.replicate CNI.nonceBytes '\0'
      m = BS.pack "hi"
      c = CN.cryptoBox m n pk2 sk1
      c' = BS.append (BS.pack "1") c
      p = CN.cryptoBoxOpen c n pk1 sk2
      p' = CN.cryptoBoxOpen c' n pk1 sk2
  print ("pk1", pk1)
  print ("sk1", sk1)
  print ("pk2", pk2)
  print ("sk2", sk2)
  print ("msg", m)
  print ("nonce", n)
  print ("ctxt", c)
  print ("bad ctxt", c')
  print ("ptxt", p)
  print ("bad ptxt", p')
