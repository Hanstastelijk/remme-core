# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: transaction.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='transaction.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x11transaction.proto\"2\n\x12TransactionPayload\x12\x0e\n\x06method\x18\x01 \x01(\r\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x62\x06proto3')
)




_TRANSACTIONPAYLOAD = _descriptor.Descriptor(
  name='TransactionPayload',
  full_name='TransactionPayload',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='method', full_name='TransactionPayload.method', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data', full_name='TransactionPayload.data', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=21,
  serialized_end=71,
)

DESCRIPTOR.message_types_by_name['TransactionPayload'] = _TRANSACTIONPAYLOAD
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TransactionPayload = _reflection.GeneratedProtocolMessageType('TransactionPayload', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTIONPAYLOAD,
  __module__ = 'transaction_pb2'
  # @@protoc_insertion_point(class_scope:TransactionPayload)
  ))
_sym_db.RegisterMessage(TransactionPayload)


# @@protoc_insertion_point(module_scope)
