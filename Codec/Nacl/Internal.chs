{-# LANGUAGE CPP, ForeignFunctionInterface #-}
module Codec.Nacl.Internal where
import Foreign
import Foreign.C.Types
import Foreign.Marshal.Array
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BSU

#include <crypto_box.h>

{#enum define PublicKeyBytes {
    crypto_box_PUBLICKEYBYTES as PublicKeyBytes
} deriving (Eq)#}

publicKeyBytes :: Int
publicKeyBytes = fromEnum PublicKeyBytes

{#enum define SecretKeyBytes {
    crypto_box_SECRETKEYBYTES as SecretKeyBytes
} deriving (Eq)#}

secretKeyBytes :: Int
secretKeyBytes = fromEnum SecretKeyBytes

{#enum define BeforeNmBytes {
    crypto_box_BEFORENMBYTES as BeforeNmBytes
} deriving (Eq)#}

beforeNmBytes :: Int
beforeNmBytes = fromEnum BeforeNmBytes

{#enum define NonceBytes {
    crypto_box_NONCEBYTES as NonceBytes
} deriving (Eq)#}

{-| The length of a crypto_box nonce. -}
nonceBytes :: Int
nonceBytes = fromEnum NonceBytes

{#enum define ZeroBytes {
    crypto_box_ZEROBYTES as ZeroBytes
} deriving (Eq)#}

zeroBytes :: Int
zeroBytes = fromEnum ZeroBytes

{#enum define BoxZeroBytes {
    crypto_box_BOXZEROBYTES as BoxZeroBytes
} deriving (Eq)#}

boxZeroBytes :: Int
boxZeroBytes = fromEnum BoxZeroBytes

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

unsafeWithData :: BS.ByteString -> (Ptr CUChar -> IO a) -> IO a
unsafeWithData xs f = BSU.unsafeUseAsCString xs $
    \cp -> f (castPtr cp)

withData :: BS.ByteString -> (Ptr CUChar -> IO a) -> IO a
withData xs f = BS.useAsCString xs $
    \cp -> f (castPtr cp)

unsafeWithDataLen :: BS.ByteString -> ((Ptr CUChar, CULLong) -> IO a) -> IO a
unsafeWithDataLen xs f = BSU.unsafeUseAsCStringLen xs $
    \(cp,cl) -> f ((castPtr cp), (fromIntegral cl))

withDataLen :: BS.ByteString -> ((Ptr CUChar, CULLong) -> IO a) -> IO a
withDataLen xs f = BS.useAsCStringLen xs $
    \(cp,cl) -> f ((castPtr cp), (fromIntegral cl))

withPK :: (Ptr CUChar -> IO a) -> IO a
withPK m = do
  let pkb = fromEnum PublicKeyBytes
  allocaArray pkb $ \p -> m p

withSK :: (Ptr CUChar -> IO a) -> IO a
withSK m = do
  let skb = fromEnum SecretKeyBytes
  allocaArray skb $ \p -> m p

fromPK :: Ptr CUChar -> IO BS.ByteString
fromPK p = BS.packCStringLen (castPtr p, fromEnum PublicKeyBytes)

fromSK :: Ptr CUChar -> IO BS.ByteString
fromSK p = BS.packCStringLen (castPtr p, fromEnum SecretKeyBytes)

{#fun unsafe crypto_box_curve25519xsalsa20poly1305_ref as cryptoBox
  { unsafeWithData* `BS.ByteString' -- c
  , withDataLen* `BS.ByteString'&   -- m, mlen
  , withData* `BS.ByteString'       -- n
  , withData* `BS.ByteString'       -- pk
  , withData* `BS.ByteString'       -- sk
  } -> `Int' #}

{#fun unsafe crypto_box_curve25519xsalsa20poly1305_ref_open as cryptoBoxOpen
  { unsafeWithData* `BS.ByteString' -- m
  , withDataLen* `BS.ByteString'&   -- c, clen
  , withData* `BS.ByteString'       -- n
  , withData* `BS.ByteString'       -- pk
  , withData* `BS.ByteString'       -- sk
  } -> `Int' #}

{#fun unsafe crypto_box_curve25519xsalsa20poly1305_ref_keypair as keypair
  { withPK- `BS.ByteString' fromPK* -- pk
  , withSK- `BS.ByteString' fromSK* -- sk
  } -> `Int' #}
