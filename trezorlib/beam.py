# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from . import messages
from .tools import expect, CallException, normalize_nfc


@expect(messages.BeamConfirmResponseMessage, field='text')
def display_message(client, text, show_display=True):
    return client.call(
        messages.BeamDisplayMessage(text=text, show_display=show_display)
    )

@expect(messages.BeamSignedMessage)
def sign_message(client, message, show_display=True):
    return client.call(
        messages.BeamSignMessage(msg=message, show_display=show_display)
    )

def verify_message(client, nonce_pub_x, nonce_pub_y, sign_k, pk_x, pk_y, message):
    nonce_pub_x = hex_str_to_bytearray(nonce_pub_x, 'Nonce X', True)
    nonce_pub_y = hex_str_to_bytearray(nonce_pub_y, 'Nonce Y', True)
    sign_k = hex_str_to_bytearray(sign_k, 'K', True)
    pk_x = hex_str_to_bytearray(pk_x, 'PK X', True)
    pk_y = hex_str_to_bytearray(pk_y, 'PK Y', True)
    message=normalize_nfc(message)

    try:
        signature = messages.BeamSignature(nonce_pub_x=nonce_pub_x, nonce_pub_y=nonce_pub_y, sign_k=sign_k)
        public_key = messages.BeamPublicKey(pub_x=pk_x, pub_y=pk_y)
        resp = client.call(
            messages.BeamVerifyMessage(
                signature=signature, public_key=public_key, message=message
            )
        )
    except CallException as e:
        resp = e
    if isinstance(resp, messages.Success):
        return True
    return False

@expect(messages.BeamPublicKey)
def get_public_key(client, show_display=True):
    return client.call(
        messages.BeamGetPublicKey(show_display=show_display)
    )

def hex_str_to_bytearray(hex_data, name='', print_info=False):
    if hex_data.startswith('0x'):
        hex_data = hex_data[2:]
        if print_info:
            print('Converted {}: {}'.format(name, hex_data))

    return bytearray.fromhex(hex_data)
