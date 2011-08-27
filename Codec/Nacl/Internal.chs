{-# LANGUAGE ForeignFunctionInterface #-}
module Codec.Nacl.Internal where
import Foreign
import Foreign.C.Types
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BSU

#include <crypto_box.h>

{#enum define PublicKeyBytes {
    crypto_box_PUBLICKEYBYTES as PublicKeyBytes
} deriving (Eq)#}

{#enum define SecretKeyBytes {
    crypto_box_SECRETKEYBYTES as SecretKeyBytes
} deriving (Eq)#}

{#enum define BeforeNmBytes {
    crypto_box_BEFORENMBYTES as BeforeNmBytes
} deriving (Eq)#}

{#enum define NonceBytes {
    crypto_box_NONCEBYTES as NonceBytes
} deriving (Eq)#}

{#enum define ZeroBytes {
    crypto_box_ZEROBYTES as ZeroBytes
} deriving (Eq)#}

{#enum define BoxZeroBytes {
    crypto_box_BOXZEROBYTES as BoxZeroBytes
} deriving (Eq)#}

{-
     const unsigned char pk[crypto_box_PUBLICKEYBYTES];
     const unsigned char sk[crypto_box_SECRETKEYBYTES];
     const unsigned char n[crypto_box_NONCEBYTES];
     const unsigned char m[...]; 
     unsigned long long mlen;
     unsigned char c[...];

     crypto_box(c,m,mlen,n,pk,sk);

     extern int crypto_box_curve25519xsalsa20poly1305_ref(
         unsigned char *,
         const unsigned char *,
         unsigned long long,
         const unsigned char *,
         const unsigned char *,
         const unsigned char *);
-}

unsafeFromData :: BS.ByteString -> (Ptr CUChar -> IO a) -> IO a
unsafeFromData xs f = BSU.unsafeUseAsCString xs $
    \cp -> f (castPtr cp)

fromData :: BS.ByteString -> (Ptr CUChar -> IO a) -> IO a
fromData xs f = BS.useAsCString xs $
    \cp -> f (castPtr cp)

unsafeFromDataLen :: BS.ByteString -> ((Ptr CUChar, CULLong) -> IO a) -> IO a
unsafeFromDataLen xs f = BSU.unsafeUseAsCStringLen xs $
    \(cp,cl) -> f ((castPtr cp), (fromIntegral cl))

fromDataLen :: BS.ByteString -> ((Ptr CUChar, CULLong) -> IO a) -> IO a
fromDataLen xs f = BS.useAsCStringLen xs $
    \(cp,cl) -> f ((castPtr cp), (fromIntegral cl))

--toData :: Int -> (Ptr CUChar -> IO z) -> IO BS.ByteString
--toData sz f = do
--    alloca $ \bp ->
--    allocaArray sz $ \m -> do
--        f m bp
--        s <- peek bp
--        packCStringLen (castPtr m, fromIntegral s)

{#fun unsafe crypto_box_curve25519xsalsa20poly1305_ref as cryptoBox
  { fromData* `BS.ByteString'
  , fromDataLen* `BS.ByteString'&
  , fromData* `BS.ByteString'
  , fromData* `BS.ByteString'
  , fromData* `BS.ByteString'
  } -> `Int' #}
