# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import re
from typing import AsyncGenerator, List, Any, Optional, AnyStr, Match


def user_dir(appname: str) -> Optional[str]:
    if os.name == 'posix':
        return os.path.join(os.environ["HOME"], ".%s" % appname.lower())
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], appname.capitalize())
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], appname.capitalize())
    else:
        # raise Exception("No home directory found in environment variables.")
        return


async def alist(generator: AsyncGenerator[Any, None]) -> List[Any]:
    return [i async for i in generator]


def is_hex(text: str) -> Optional[Match[AnyStr]]:
    regex = '^[0-9a-fA-F]*$'
    if isinstance(text, bytes):
        regex = regex.encode()
    return re.match(regex, text)
