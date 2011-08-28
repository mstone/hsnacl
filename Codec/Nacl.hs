{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Codec.Nacl (
    PublicKey
  , SecretKey
  , keypair
  , cryptoBox
  , cryptoBoxOpen
) where
import Foreign
import Foreign.C.Types
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BSU
import qualified Codec.Nacl.Internal as CNI

{-| @'PublicKey'@ is the type of public keys -}
newtype PublicKey = PK { unPK :: BS.ByteString } 
  deriving (Eq, Show, Ord)

{-| @'SecretKey'@ is the type of public keys -}
newtype SecretKey = SK { unSK :: BS.ByteString }
  deriving (Eq, Show, Ord)

{-| @'keypair'@ calculates a fresh keypair.  -}
keypair :: IO (PublicKey, SecretKey)
keypair = do
  (_, pk', sk') <- CNI.keypair
  return (PK pk', SK sk')

{-|
  @'cryptoBox' m n pk sk@ calculates the ciphertext of message @m@ and
  nonce @n@ encrypted and authenticated from @sk@ to @pk@.

  Nonce @n@ should be exactly 'CNI.nonceBytes' long.
-}
cryptoBox :: BS.ByteString -- ^ message
          -> BS.ByteString -- ^ nonce
          -> PublicKey -- ^ public key
          -> SecretKey -- ^ secret key
          -> BS.ByteString -- ^ ciphertext
cryptoBox m n (PK pk) (SK sk) = unsafePerformIO $ do
  case BS.length pk of
    x | x == fromEnum CNI.PublicKeyBytes -> return ()
    _ -> fail "incorrect public-key length"
  case BS.length sk of
    x | x == fromEnum CNI.SecretKeyBytes -> return ()
    _ -> fail "incorrect secret-key length"
  case BS.length n of
    x | x == fromEnum CNI.NonceBytes -> return ()
    _ -> fail "incorrect nonce length"
  let zb = CNI.zeroBytes
      mlen = (zb + BS.length m)
      mpad = BS.append (BS.replicate zb '\0') m
      cpad = BS.replicate mlen '\0'
  _ <- CNI.cryptoBox cpad mpad n pk sk
  return $ BS.drop CNI.boxZeroBytes cpad

{-|
  @'cryptoBoxOpen' m n pk sk@ calculates the plaintext of enciphered
  message @c@ and nonce @n@ decrypted and authenticated from @pk@ to
  @sk@.

  Nonce @n@ should be exactly 'CNI.nonceBytes' long.
-}
cryptoBoxOpen :: BS.ByteString -- ^ ciphertext
              -> BS.ByteString -- ^ nonce
              -> PublicKey -- ^ public key
              -> SecretKey -- ^ secret key
              -> Maybe BS.ByteString -- ^ message
cryptoBoxOpen m n (PK pk) (SK sk) = unsafePerformIO $ do
  case BS.length pk of
    x | x == fromEnum CNI.PublicKeyBytes -> return ()
    _ -> fail "incorrect public-key length"
  case BS.length sk of
    x | x == fromEnum CNI.SecretKeyBytes -> return ()
    _ -> fail "incorrect secret-key length"
  case BS.length n of
    x | x == fromEnum CNI.NonceBytes -> return ()
    _ -> fail "incorrect nonce length"
  let bzb = CNI.boxZeroBytes
      clen = (bzb + BS.length m)
      cpad = BS.append (BS.replicate bzb '\0') m
      mpad = BS.replicate clen '\0'
  ret <- CNI.cryptoBoxOpen mpad cpad n pk sk
  case ret of
    0 -> return $ Just $ BS.drop CNI.zeroBytes mpad
    _ -> return Nothing
