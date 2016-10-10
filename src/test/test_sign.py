import unittest
from util import *

FLAG_ECDSA, FLAG_SCHNORR = 1, 2


class SignTests(unittest.TestCase):

    def do_sign_compact(self, priv_key_hex, message_hex, flags):
        priv_key, priv_key_len = make_cbuffer(priv_key_hex)
        message, message_len = make_cbuffer(message_hex)
        out_buf, out_len = make_cbuffer('00' * 64)
        ret = wally_ec_sign_compact(priv_key, priv_key_len, message, message_len,
                                    flags, out_buf, out_len)
        return ret, out_buf

    def test_sign_compact(self):

        # Invalid inputs
        FLAGS_BOTH = FLAG_ECDSA | FLAG_SCHNORR
        priv_ok, msg_ok, flags_ok = ('11' * 32), ('22' * 32), FLAG_ECDSA
        for c in [(None,        msg_ok,      flags_ok),         # Null priv_key
                  (('11' * 33), msg_ok,      flags_ok),         # Wrong priv_key len
                  (priv_ok,     None,        flags_ok),         # Null message
                  (priv_ok,     ('11' * 33), flags_ok),         # Wrong message len
                  (priv_ok,     None,        flags_ok),         # Null message
                  (priv_ok,     msg_ok,      0),                # No flags set
                  (priv_ok,     msg_ok,      FLAG_SCHNORR),     # Not implemented
                  (priv_ok,     msg_ok,      FLAGS_BOTH),       # Mutually exclusive
                  (priv_ok,     msg_ok,      0x4),              # Unknown flag
                  ]:
            priv_key_hex, message_hex, flags = c
            ret, _ = self.do_sign_compact(priv_key_hex, message_hex, flags)
            self.assertEqual(ret, WALLY_EINVAL)


if __name__ == '__main__':
    unittest.main()
