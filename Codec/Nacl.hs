module Codec.Nacl where
import Foreign
import Foreign.C.Types
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BSU
import qualified Codec.Nacl.Internal as CNI

{-|
  @'cryptoBox' m n pk sk@ calculates the ciphertext of message @m@ and
nonce 'n' encrypted and authenticated from @sk@ to @pk@.
-}
cryptoBox :: ByteString -- ^ message
          -> ByteString -- ^ nonce
          -> ByteString -- ^ public key
          -> ByteString -- ^ secret key
          -> ByteString -- ^ ciphertext
cryptoBox m n pk sk = unsafePerformIO $ do
  case BS.length pk of
    fromEnum CNI.PublicKeyBytes -> return ()
    _ -> fail "incorrect public-key length"
  case BS.length sk of
    fromEnum CNI.SecretKeyBytes -> return ()
    _ -> fail "incorrect secret-key length"
  case BS.length n of
    fromEnum CNI.NonceBytes -> return ()
    _ -> fail "incorrect nonce length"
  let zb = fromEnum CNI.ZeroBytes
      mlen = (zb + BS.length m)
      mpad = BS.append (BS.replicate '\0' zb) m
      cpad = BS.replicate '\0' mlen
  _ <- CNI.cryptoBox cpad mpad n pk sk
  return $ BS.drop zb
