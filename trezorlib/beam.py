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

def verify_message(client, nonce_pub_x, nonce_pub_y, sign_k, pk, message):
    if nonce_pub_x.startswith('0x'):
        nonce_pub_x = nonce_pub_x[2:]
        print('X: {}'.format(nonce_pub_x))
    if nonce_pub_y.startswith('0x'):
        nonce_pub_y = nonce_pub_y[2:]
        print('Y: {}'.format(nonce_pub_y))
    if sign_k.startswith('0x'):
        sign_k = sign_k[2:]
        print('K: {}'.format(sign_k))
    if pk.startswith('0x'):
        pk = pk[2:]
        print('PK: {}'.format(pk))
    nonce_pub_x = bytearray.fromhex(nonce_pub_x)
    nonce_pub_y = bytearray.fromhex(nonce_pub_y)
    sign_k = bytearray.fromhex(sign_k)
    pk = bytearray.fromhex(pk)
    message=normalize_nfc(message)

    try:
        signature = messages.BeamSignature(nonce_pub_x=nonce_pub_x, nonce_pub_y=nonce_pub_y, sign_k=sign_k)
        resp = client.call(
            messages.BeamVerifyMessage(
                signature=signature, xpub=pk, message=message
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
