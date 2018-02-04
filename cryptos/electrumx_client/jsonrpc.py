# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Classes for acting as a peer over a transport and speaking the JSON
RPC versions 1.0 and 2.0.
JSONSessionBase can use an arbitrary transport.
JSONSession integrates asyncio.Protocol to provide the transport.
'''

import asyncio
import collections
import inspect
import json
import numbers
import time
import traceback

from . import util


class RPCError(Exception):
    '''RPC handlers raise this error.'''
    def __init__(self, msg, code=-1, **kw_args):
        super().__init__(**kw_args)
        self.msg = msg
        self.code = code


class JSONRPC(object):
    '''Base class of JSON RPC versions.'''

    # See http://www.jsonrpc.org/specification
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_ARGS = -32602
    INTERNAL_ERROR = -32603

    # Codes for this library
    INVALID_RESPONSE = -100
    ERROR_CODE_UNAVAILABLE = -101
    REQUEST_TIMEOUT = -102
    FATAL_ERROR = -103

    ID_TYPES = (type(None), str, numbers.Number)
    HAS_BATCHES = False

    @classmethod
    def canonical_error(cls, error):
        '''Convert an error to a JSON RPC 2.0 error.
        Handlers then only have a single form of error to deal with.
        '''
        if isinstance(error, int):
            error = {'code': error}
        elif isinstance(error, str):
            error = {'message': error}
        elif not isinstance(error, dict):
            error = {'data': error}
        error['code'] = error.get('code', JSONRPC.ERROR_CODE_UNAVAILABLE)
        error['message'] = error.get('message', 'error message unavailable')
        return error

    @classmethod
    def timeout_error(cls):
        return {'message': 'request timed out',
                'code': JSONRPC.REQUEST_TIMEOUT}


class JSONRPCv1(JSONRPC):
    '''JSON RPC version 1.0.'''

    @classmethod
    def request_payload(cls, id_, method, params=None):
        '''JSON v1 request payload.  Params is mandatory.'''
        return {'method': method, 'params': params or [], 'id': id_}

    @classmethod
    def notification_payload(cls, method, params=None):
        '''JSON v1  notification payload.  Params and id are mandatory.'''
        return {'method': method, 'params': params or [], 'id': None}

    @classmethod
    def response_payload(cls, result, id_):
        '''JSON v1 response payload.  error is present and None.'''
        return {'id': id_, 'result': result, 'error': None}

    @classmethod
    def error_payload(cls, message, code, id_):
        '''JSON v1 error payload.  result is present and None.'''
        return {'id': id_, 'result': None,
                'error': {'message': message, 'code': code}}

    @classmethod
    def handle_response(cls, handler, payload):
        '''JSON v1 response handler.  Both 'error' and 'result'
        should exist with exactly one being None.
        Unfortunately many 1.0 clients behave like 2.0, and just send
        one or the other.
        '''
        error = payload.get('error')
        if error is None:
            handler(payload.get('result'), None)
        else:
            handler(None, cls.canonical_error(error))

    @classmethod
    def is_request(cls, payload):
        '''Returns True if the payload (which has a method) is a request.
        False means it is a notification.'''
        return payload.get('id') is not None


class JSONRPCv2(JSONRPC):
    '''JSON RPC version 2.0.'''

    HAS_BATCHES = True

    @classmethod
    def request_payload(cls, id_, method, params=None):
        '''JSON v2 request payload.  Params is optional.'''
        payload = {'jsonrpc': '2.0', 'method': method, 'id': id_}
        if params:
            payload['params'] = params
        return payload

    @classmethod
    def notification_payload(cls, method, params=None):
        '''JSON v2  notification payload.  There must be no id.'''
        payload = {'jsonrpc': '2.0', 'method': method}
        if params:
            payload['params'] = params
        return payload

    @classmethod
    def response_payload(cls, result, id_):
        '''JSON v2 response payload.  error is not present.'''
        return {'jsonrpc': '2.0', 'id': id_, 'result': result}

    @classmethod
    def error_payload(cls, message, code, id_):
        '''JSON v2 error payload.  result is not present.'''
        return {'jsonrpc': '2.0', 'id': id_,
                'error': {'message': message, 'code': code}}

    @classmethod
    def handle_response(cls, handler, payload):
        '''JSON v2 response handler.  Exactly one of 'error' and 'result'
        must exist.  Errors must have 'code' and 'message' members.
        '''
        if 'error' in payload:
            handler(None, cls.canonical_error(payload['error']))
        elif 'result' in payload:
            handler(payload['id'], payload['result'], None)
        else:
            error = {'message': 'no error or result returned',
                     'code': JSONRPC.INVALID_RESPONSE}
            handler(None, cls.canonical_error(error))

    @classmethod
    def batch_size(cls, parts):
        '''Return the size of a JSON batch from its parts.'''
        return sum(len(part) for part in parts) + 2 * len(parts)

    @classmethod
    def batch_bytes(cls, parts):
        '''Return the bytes of a JSON batch from its parts.'''
        if parts:
            return b'[' + b', '.join(parts) + b']'
        return b''

    @classmethod
    def is_request(cls, payload):
        '''Returns True if the payload (which has a method) is a request.
        False means it is a notification.'''
        return 'id' in payload


class JSONRPCCompat(JSONRPC):
    '''Intended to be used until receiving a response from the peer, at
    which point detect_version should be used to choose which version
    to use.
    Sends requests compatible with v1 and v2.  Errors cannot be
    compatible so v2 errors are sent.
    Does not send responses or notifications, nor handle responses.
    '''
    @classmethod
    def request_payload(cls, id_, method, params=None):
        '''JSON v2 request payload but with params present.'''
        return {'jsonrpc': '2.0', 'id': id_,
                'method': method, 'params': params or []}

    @classmethod
    def error_payload(cls, message, code, id_):
        '''JSON v2 error payload.  result is not present.'''
        return {'jsonrpc': '2.0', 'id': id_,
                'error': {'message': message, 'code': code}}

    @classmethod
    def detect_version(cls, payload):
        '''Return a best guess at a version compatible with the received
        payload.
        Return None if one cannot be determined.
        '''
        def item_version(item):
            if isinstance(item, dict):
                version = item.get('jsonrpc')
                if version is None:
                    return JSONRPCv1
                if version == '2.0':
                    return JSONRPCv2
            return None

        if isinstance(payload, list) and payload:
            version = item_version(payload[0])
            # If a batch return at least JSONRPCv2
            if version in (JSONRPCv1, None):
                version = JSONRPCv2
        else:
            version = item_version(payload)

        return version


class JSONSessionBase(util.LoggedClass):
    '''Acts as the application layer session, communicating via JSON RPC
    over an underlying transport.
    Processes incoming and sends outgoing requests, notifications and
    responses.  Incoming messages are queued.  When the queue goes
    from empty
    '''
    _next_session_id = 0
    _pending_reqs = {}    # Outgoing requests waiting for a response

    @classmethod
    def next_session_id(cls):
        '''Return the next unique session ID.'''
        session_id = cls._next_session_id
        cls._next_session_id += 1
        return session_id

    def _pending_request_keys(self):
        '''Return a generator of pending request keys for this session.'''
        return [key for key in self._pending_reqs if key[0] is self]

    def has_pending_requests(self):
        '''Return True if this session has pending requests.'''
        return bool(self._pending_request_keys())

    def pop_response_handler(self, msg_id):
        '''Return the response handler for the given message ID.'''
        return self._pending_reqs.pop((self, msg_id), (None, None))[0]

    def timeout_session(self):
        '''Trigger timeouts for all of the session's pending requests.'''
        self._timeout_requests(self._pending_request_keys())

    @classmethod
    def timeout_check(cls):
        '''Trigger timeouts where necessary for all pending requests.'''
        now = time.time()
        keys = [key for key, value in cls._pending_reqs.items()
                if value[1] < now]
        cls._timeout_requests(keys)

    @classmethod
    def _timeout_requests(cls, keys):
        '''Trigger timeouts for the given lookup keys.'''
        values = [cls._pending_reqs.pop(key) for key in keys]
        handlers = [handler for handler, timeout in values]
        timeout_error = JSONRPC.timeout_error()
        for handler in handlers:
            handler(None, timeout_error)

    def __init__(self, version=JSONRPCCompat):
        super().__init__()

        # Parts of an incomplete JSON line.  We buffer them until
        # getting a newline.
        self.parts = []
        self.version = version
        self.log_me = False
        self.session_id = None
        # Count of incoming complete JSON requests and the time of the
        # last one.  A batch counts as just one here.
        self.last_recv = time.time()
        self.send_count = 0
        self.send_size = 0
        self.recv_size = 0
        self.recv_count = 0
        self.error_count = 0
        self.pause = False
        # Handling of incoming items
        self.items = collections.deque()
        self.items_events ={}
        self.items_event = asyncio.Event()
        self.batch_results = []
        # Handling of outgoing requests
        self.next_request_id = 0
        # If buffered incoming data exceeds this the connection is closed
        self.max_buffer_size = 1000000
        self.max_send = 50000
        self.close_after_send = False

    def pause_writing(self):
        '''Transport calls when the send buffer is full.'''
        self.log_info('pausing processing whilst socket drains')
        self.pause = True

    def resume_writing(self):
        '''Transport calls when the send buffer has room.'''
        self.log_info('resuming processing')
        self.pause = False

    def is_oversized(self, length, id_):
        '''Return an error payload if the given outgoing message size is too
        large, or False if not.
        '''
        if self.max_send and length > max(1000, self.max_send):
            msg = 'response too large (at least {:d} bytes)'.format(length)
            return self.error_bytes(msg, JSONRPC.INVALID_REQUEST, id_)
        return False

    def send_binary(self, binary):
        '''Pass the bytes through to the transport.
        Close the connection if close_after_send is set.
        '''
        if self.is_closing():
            return
        self.using_bandwidth(len(binary))
        self.send_count += 1
        self.send_size += len(binary)
        self.send_bytes(binary)
        if self.close_after_send:
            self.close_connection()

    def payload_id(self, payload):
        '''Extract and return the ID from the payload.
        Returns None if it is missing or invalid.'''
        try:
            return self.check_payload_id(payload)
        except RPCError:
            return None

    def check_payload_id(self, payload):
        '''Extract and return the ID from the payload.
        Raises an RPCError if it is missing or invalid.'''
        if 'id' not in payload:
            raise RPCError('missing id', JSONRPC.INVALID_REQUEST)

        id_ = payload['id']
        if not isinstance(id_, self.version.ID_TYPES):
            raise RPCError('invalid id type {}'.format(type(id_)),
                           JSONRPC.INVALID_REQUEST)
        return id_

    def request_bytes(self, id_, method, params=None):
        '''Return the bytes of a JSON request.'''
        payload = self.version.request_payload(id_, method, params)
        return self.encode_payload(payload)

    def notification_bytes(self, method, params=None):
        payload = self.version.notification_payload(method, params)
        return self.encode_payload(payload)

    def response_bytes(self, result, id_):
        '''Return the bytes of a JSON response.'''
        return self.encode_payload(self.version.response_payload(result, id_))

    def error_bytes(self, message, code, id_=None):
        '''Return the bytes of a JSON error.
        Flag the connection to close on a fatal error or too many errors.'''
        version = self.version
        self.error_count += 1
        if not self.close_after_send:
            fatal_log = None
            if code in (version.PARSE_ERROR, version.INVALID_REQUEST,
                        version.FATAL_ERROR):
                fatal_log = message
            elif self.error_count >= 10:
                fatal_log = 'too many errors, last: {}'.format(message)
            if fatal_log:
                self.log_info(fatal_log)
                self.close_after_send = True
        return self.encode_payload(self.version.error_payload
                                   (message, code, id_))

    def encode_payload(self, payload):
        '''Encode a Python object as binary bytes.'''
        assert isinstance(payload, dict)

        id_ = payload.get('id')
        try:
            binary = json.dumps(payload).encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.log_error(msg)
            binary = self.error_bytes(msg, JSONRPC.INTERNAL_ERROR, id_)

        error_bytes = self.is_oversized(len(binary), id_)
        return error_bytes or binary

    def decode_message(self, payload):
        '''Decode a binary message and pass it on to process_single_item or
        process_batch as appropriate.
        Messages that cannot be decoded are logged and dropped.
        '''
        try:
            payload = payload.decode()
        except UnicodeDecodeError as e:
            msg = 'cannot decode message: {}'.format(e)
            self.send_error(msg, JSONRPC.PARSE_ERROR)
            return

        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.send_error(msg, JSONRPC.PARSE_ERROR)
            return

        if self.version is JSONRPCCompat:
            # Attempt to detect peer's JSON RPC version
            version = self.version.detect_version(payload)
            if not version:
                version = JSONRPCv2
                self.log_info('unable to detect JSON RPC version, using 2.0')
            self.version = version

        # Batches must have at least one object.
        if payload == [] and self.version.HAS_BATCHES:
            self.send_error('empty batch', JSONRPC.INVALID_REQUEST)
            return

        self.items.append(payload)
        self.items_events[payload['id']].set()

    async def process_batch(self, batch, count):
        '''Processes count items from the batch according to the JSON 2.0
        spec.
        If any remain, puts what is left of the batch back in the deque
        and returns None.  Otherwise returns the binary batch result.'''
        results = self.batch_results
        self.batch_results = []

        for n in range(count):
            item = batch.pop()
            result = await self.process_single_item(item)
            if result:
                results.append(result)

        if not batch:
            return self.version.batch_bytes(results)

        error_bytes = self.is_oversized(self.batch_size(results), None)
        if error_bytes:
            return error_bytes

        self.items.appendleft(item)
        self.batch_results = results
        return None

    async def process_single_item(self, payload):
        '''Handle a single JSON request, notification or response.
        If it is a request, return the binary response, oterhwise None.'''
        if self.log_me:
            self.log_info('processing {}'.format(payload))

        if not isinstance(payload, dict):
            return self.error_bytes('request must be a dictionary',
                                    JSONRPC.INVALID_REQUEST)

        try:
            # Requests and notifications must have a method.
            if 'method' in payload:
                if self.version.is_request(payload):
                    return await self.process_single_request(payload)
                else:
                    await self.process_single_notification(payload)
            else:
                self.process_single_response(payload)

            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            self.log_error(traceback.format_exc())
            return self.error_bytes('internal error processing request',
                                    JSONRPC.INTERNAL_ERROR,
                                    self.payload_id(payload))

    async def process_single_request(self, payload):
        '''Handle a single JSON request and return the binary response.'''
        try:
            result = await self.handle_payload(payload, self.request_handler)
            return self.response_bytes(result, payload['id'])
        except RPCError as e:
            return self.error_bytes(e.msg, e.code, self.payload_id(payload))
        except asyncio.CancelledError:
            raise
        except Exception:
            self.log_error(traceback.format_exc())
            return self.error_bytes('internal error processing request',
                                    JSONRPC.INTERNAL_ERROR,
                                    self.payload_id(payload))

    async def process_single_notification(self, payload):
        '''Handle a single JSON notification.'''
        try:
            await self.handle_payload(payload, self.notification_handler)
        except RPCError:
            pass
        except Exception:
            self.log_error(traceback.format_exc())

    def process_single_response(self, payload):
        '''Handle a single JSON response.'''
        try:
            id_ = self.check_payload_id(payload)
            handler = self.pop_response_handler(id_)
            if handler:
                self.version.handle_response(handler, payload)
            else:
                self.log_info('response for unsent id {}'.format(id_),
                              throttle=True)
        except RPCError:
            pass
        except Exception:
            self.log_error(traceback.format_exc())

    async def handle_payload(self, payload, get_handler):
        '''Handle a request or notification payload given the handlers.'''
        # An argument is the value passed to a function parameter...
        args = payload.get('params', [])
        method = payload.get('method')

        if not isinstance(method, str):
            raise RPCError("invalid method type {}".format(type(method)),
                           JSONRPC.INVALID_REQUEST)

        handler = get_handler(method)
        if not handler:
            raise RPCError("unknown method: '{}'".format(method),
                           JSONRPC.METHOD_NOT_FOUND)

        if not isinstance(args, (list, dict)):
            raise RPCError('arguments should be an array or dictionary',
                           JSONRPC.INVALID_REQUEST)

        params = inspect.signature(handler).parameters
        names = list(params)
        min_args = sum(p.default is p.empty for p in params.values())

        if len(args) < min_args:
            raise RPCError('too few arguments to {}: expected {:d} got {:d}'
                           .format(method, min_args, len(args)),
                           JSONRPC.INVALID_ARGS)

        if len(args) > len(params):
            raise RPCError('too many arguments to {}: expected {:d} got {:d}'
                           .format(method, len(params), len(args)),
                           JSONRPC.INVALID_ARGS)

        if isinstance(args, list):
            kw_args = {name: arg for name, arg in zip(names, args)}
        else:
            kw_args = args
            bad_names = ['<{}>'.format(name) for name in args
                         if name not in names]
            if bad_names:
                raise RPCError('invalid parameter names: {}'
                               .format(', '.join(bad_names)))

        if inspect.iscoroutinefunction(handler):
            return await handler(**kw_args)
        else:
            return handler(**kw_args)

    # ---- External Interface ----

    async def process_pending_items(self, limit=8):
        '''Processes up to LIMIT pending items asynchronously.'''
        while limit > 0 and self.items:
            item = self.items.popleft()

            if isinstance(item, list) and self.version.HAS_BATCHES:
                count = min(limit, len(item))
                binary = await self.process_batch(item, count)
                limit -= count
            else:
                binary = await self.process_single_item(item)
                limit -= 1

            if binary:
                self.send_binary(binary)

    def count_pending_items(self):
        '''Counts the number of pending items.'''
        return sum(len(item) if isinstance(item, list) else 1
                   for item in self.items)

    def connection_made(self):
        '''Call when an incoming client connection is established.'''
        self.session_id = self.next_session_id()
        self.log_prefix = '[{:d}] '.format(self.session_id)

    def data_received(self, data):
        '''Underlying transport calls this when new data comes in.
        Look for newline separators terminating full requests.
        '''
        if self.is_closing():
            return
        self.using_bandwidth(len(data))
        self.recv_size += len(data)

        # Close abusive connections where buffered data exceeds limit
        buffer_size = len(data) + sum(len(part) for part in self.parts)
        if buffer_size > self.max_buffer_size:
            self.log_error('read buffer of {:,d} bytes over {:,d} byte limit'
                           .format(buffer_size, self.max_buffer_size))
            self.close_connection()
            return

        while True:
            npos = data.find(ord('\n'))
            if npos == -1:
                self.parts.append(data)
                break
            tail, data = data[:npos], data[npos + 1:]
            parts, self.parts = self.parts, []
            parts.append(tail)
            self.recv_count += 1
            self.last_recv = time.time()
            self.decode_message(b''.join(parts))

    def send_error(self, message, code, id_=None):
        '''Send a JSON error.'''
        self.send_binary(self.error_bytes(message, code, id_))

    def send_request(self, handler, method, params=None, timeout=30):
        '''Sends a request and arranges for handler to be called with the
        response when it comes in.
        A call to request_timeout_check() will result in pending
        responses that have been waiting more than timeout seconds to
        call the handler with a REQUEST_TIMEOUT error.
        '''
        id_ = self.next_request_id
        self.next_request_id += 1
        self.send_binary(self.request_bytes(id_, method, params))
        self.items_events[id_] = asyncio.Event()
        self._pending_reqs[(self, id_)] = (handler, time.time() + timeout)
        return  id_

    def send_notification(self, method, params=None):
        '''Send a notification.'''
        self.send_binary(self.notification_bytes(method, params))

    def send_notifications(self, mp_iterable):
        '''Send an iterable of (method, params) notification pairs.
        A 1-tuple is also valid in which case there are no params.'''
        if False and self.version.HAS_BATCHES:
            parts = [self.notification_bytes(*pair) for pair in mp_iterable]
            self.send_binary(self.version.batch_bytes(parts))
        else:
            for pair in mp_iterable:
                self.send_notification(*pair)

    # -- derived classes are intended to override these functions

    # Transport layer

    def is_closing(self):
        '''Return True if the underlying transport is closing.'''
        raise NotImplementedError

    def close_connection(self):
        '''Close the connection.'''
        raise NotImplementedError

    def send_bytes(self, binary):
        '''Pass the bytes through to the underlying transport.'''
        raise NotImplementedError

    # App layer

    def using_bandwidth(self, amount):
        '''Called as bandwidth is consumed.
        Override to implement bandwidth management.
        '''
        pass

    def notification_handler(self, method):
        '''Return the handler for the given notification.
        The handler can be synchronous or asynchronous.'''
        return None

    def request_handler(self, method):
        '''Return the handler for the given request method.
        The handler can be synchronous or asynchronous.'''
        return None


class JSONSession(JSONSessionBase, asyncio.Protocol):
    '''A JSONSessionBase instance specialized for use with
    asyncio.protocol to implement the transport layer.
    The app should await on items_event, which is set when unprocessed
    incoming items remain and cleared when the queue is empty, and
    then arrange to call process_pending_items asynchronously.
    Derived classes may want to override the request and notification
    handlers.
    '''

    def __init__(self, version=JSONRPCCompat):
        super().__init__(version=version)
        self.transport = None
        self.write_buffer_high = 500000

    def peer_info(self):
        '''Returns information about the peer.'''
        try:
            # get_extra_info can throw even if self.transport is not None
            return self.transport.get_extra_info('peername')
        except Exception:
            return None

    def abort(self):
        '''Cut the connection abruptly.'''
        self.transport.abort()

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        transport.set_write_buffer_limits(high=self.write_buffer_high)
        self.transport = transport
        super().connection_made()

    def connection_lost(self, exc):
        '''Trigger timeouts of all pending requests.'''
        self.timeout_session()

    def is_closing(self):
        '''True if the underlying transport is closing.'''
        return self.transport and self.transport.is_closing()

    def close_connection(self):
        '''Close the connection.'''
        if self.transport:
            self.transport.close()

    def send_bytes(self, binary):
        '''Send JSON text over the transport.'''
        self.transport.writelines((binary, b'\n'))

    def peer_addr(self, anon=True):
        '''Return the peer address and port.'''
        peer_info = self.peer_info()
        if not peer_info:
            return 'unknown'
        if anon:
            return 'xx.xx.xx.xx:xx'
        if ':' in peer_info[0]:
            return '[{}]:{}'.format(peer_info[0], peer_info[1])
        else:
            return '{}:{}'.format(peer_info[0], peer_info[1])