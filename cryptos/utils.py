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


def android_ext_dir():
    import jnius
    env = jnius.autoclass('android.os.Environment')
    return env.getExternalStorageDirectory().getPath()

def android_data_dir():
    import jnius
    PythonActivity = jnius.autoclass('org.kivy.android.PythonActivity')
    return PythonActivity.mActivity.getFilesDir().getPath() + '/data'

def android_headers_dir(appname):
    d = android_ext_dir() + '/org.%s.%s' % (appname, appname)
    if not os.path.exists(d):
        os.mkdir(d)
    return d

def user_dir(appname):
    if 'ANDROID_DATA' in os.environ:
        return android_data_dir()
    elif os.name == 'posix':
        return os.path.join(os.environ["HOME"], ".%s" % appname.lower())
    elif "APPDATA" in os.environ:
        return os.path.join(os.environ["APPDATA"], appname.capitalize())
    elif "LOCALAPPDATA" in os.environ:
        return os.path.join(os.environ["LOCALAPPDATA"], appname.capitalize())
    else:
        #raise Exception("No home directory found in environment variables.")
        return