// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.14.0
// source: p2pke.proto

package p2pke

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type InitHello struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version         uint32     `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	TimestampTai64N []byte     `protobuf:"bytes,2,opt,name=timestamp_tai64n,json=timestampTai64n,proto3" json:"timestamp_tai64n,omitempty"`
	AuthClaim       *AuthClaim `protobuf:"bytes,3,opt,name=auth_claim,json=authClaim,proto3" json:"auth_claim,omitempty"`
}

func (x *InitHello) Reset() {
	*x = InitHello{}
	if protoimpl.UnsafeEnabled {
		mi := &file_p2pke_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InitHello) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitHello) ProtoMessage() {}

func (x *InitHello) ProtoReflect() protoreflect.Message {
	mi := &file_p2pke_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitHello.ProtoReflect.Descriptor instead.
func (*InitHello) Descriptor() ([]byte, []int) {
	return file_p2pke_proto_rawDescGZIP(), []int{0}
}

func (x *InitHello) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *InitHello) GetTimestampTai64N() []byte {
	if x != nil {
		return x.TimestampTai64N
	}
	return nil
}

func (x *InitHello) GetAuthClaim() *AuthClaim {
	if x != nil {
		return x.AuthClaim
	}
	return nil
}

type RespHello struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthClaim *AuthClaim `protobuf:"bytes,2,opt,name=auth_claim,json=authClaim,proto3" json:"auth_claim,omitempty"`
}

func (x *RespHello) Reset() {
	*x = RespHello{}
	if protoimpl.UnsafeEnabled {
		mi := &file_p2pke_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RespHello) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RespHello) ProtoMessage() {}

func (x *RespHello) ProtoReflect() protoreflect.Message {
	mi := &file_p2pke_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RespHello.ProtoReflect.Descriptor instead.
func (*RespHello) Descriptor() ([]byte, []int) {
	return file_p2pke_proto_rawDescGZIP(), []int{1}
}

func (x *RespHello) GetAuthClaim() *AuthClaim {
	if x != nil {
		return x.AuthClaim
	}
	return nil
}

type InitDone struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthClaim *AuthClaim `protobuf:"bytes,1,opt,name=auth_claim,json=authClaim,proto3" json:"auth_claim,omitempty"`
}

func (x *InitDone) Reset() {
	*x = InitDone{}
	if protoimpl.UnsafeEnabled {
		mi := &file_p2pke_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InitDone) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitDone) ProtoMessage() {}

func (x *InitDone) ProtoReflect() protoreflect.Message {
	mi := &file_p2pke_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitDone.ProtoReflect.Descriptor instead.
func (*InitDone) Descriptor() ([]byte, []int) {
	return file_p2pke_proto_rawDescGZIP(), []int{2}
}

func (x *InitDone) GetAuthClaim() *AuthClaim {
	if x != nil {
		return x.AuthClaim
	}
	return nil
}

type AuthClaim struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyX509 []byte `protobuf:"bytes,1,opt,name=key_x509,json=keyX509,proto3" json:"key_x509,omitempty"`
	Sig     []byte `protobuf:"bytes,2,opt,name=sig,proto3" json:"sig,omitempty"`
}

func (x *AuthClaim) Reset() {
	*x = AuthClaim{}
	if protoimpl.UnsafeEnabled {
		mi := &file_p2pke_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthClaim) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthClaim) ProtoMessage() {}

func (x *AuthClaim) ProtoReflect() protoreflect.Message {
	mi := &file_p2pke_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthClaim.ProtoReflect.Descriptor instead.
func (*AuthClaim) Descriptor() ([]byte, []int) {
	return file_p2pke_proto_rawDescGZIP(), []int{3}
}

func (x *AuthClaim) GetKeyX509() []byte {
	if x != nil {
		return x.KeyX509
	}
	return nil
}

func (x *AuthClaim) GetSig() []byte {
	if x != nil {
		return x.Sig
	}
	return nil
}

var File_p2pke_proto protoreflect.FileDescriptor

var file_p2pke_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x70, 0x32, 0x70, 0x6b, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7b, 0x0a,
	0x09, 0x49, 0x6e, 0x69, 0x74, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x29, 0x0a, 0x10, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x5f, 0x74, 0x61, 0x69, 0x36, 0x34, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x54, 0x61, 0x69, 0x36, 0x34, 0x6e, 0x12,
	0x29, 0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x52,
	0x09, 0x61, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x22, 0x36, 0x0a, 0x09, 0x52, 0x65,
	0x73, 0x70, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x12, 0x29, 0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x5f,
	0x63, 0x6c, 0x61, 0x69, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x52, 0x09, 0x61, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x61,
	0x69, 0x6d, 0x22, 0x35, 0x0a, 0x08, 0x49, 0x6e, 0x69, 0x74, 0x44, 0x6f, 0x6e, 0x65, 0x12, 0x29,
	0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x52, 0x09,
	0x61, 0x75, 0x74, 0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x22, 0x38, 0x0a, 0x09, 0x41, 0x75, 0x74,
	0x68, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x12, 0x19, 0x0a, 0x08, 0x6b, 0x65, 0x79, 0x5f, 0x78, 0x35,
	0x30, 0x39, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x58, 0x35, 0x30,
	0x39, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x73, 0x69, 0x67, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x62, 0x72, 0x65, 0x6e, 0x64, 0x6f, 0x6e, 0x63, 0x61, 0x72, 0x72, 0x6f, 0x6c, 0x6c,
	0x2f, 0x67, 0x6f, 0x2d, 0x70, 0x32, 0x70, 0x2f, 0x70, 0x2f, 0x70, 0x32, 0x70, 0x6b, 0x65, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_p2pke_proto_rawDescOnce sync.Once
	file_p2pke_proto_rawDescData = file_p2pke_proto_rawDesc
)

func file_p2pke_proto_rawDescGZIP() []byte {
	file_p2pke_proto_rawDescOnce.Do(func() {
		file_p2pke_proto_rawDescData = protoimpl.X.CompressGZIP(file_p2pke_proto_rawDescData)
	})
	return file_p2pke_proto_rawDescData
}

var file_p2pke_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_p2pke_proto_goTypes = []interface{}{
	(*InitHello)(nil), // 0: InitHello
	(*RespHello)(nil), // 1: RespHello
	(*InitDone)(nil),  // 2: InitDone
	(*AuthClaim)(nil), // 3: AuthClaim
}
var file_p2pke_proto_depIdxs = []int32{
	3, // 0: InitHello.auth_claim:type_name -> AuthClaim
	3, // 1: RespHello.auth_claim:type_name -> AuthClaim
	3, // 2: InitDone.auth_claim:type_name -> AuthClaim
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_p2pke_proto_init() }
func file_p2pke_proto_init() {
	if File_p2pke_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_p2pke_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InitHello); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_p2pke_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RespHello); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_p2pke_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InitDone); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_p2pke_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthClaim); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_p2pke_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_p2pke_proto_goTypes,
		DependencyIndexes: file_p2pke_proto_depIdxs,
		MessageInfos:      file_p2pke_proto_msgTypes,
	}.Build()
	File_p2pke_proto = out.File
	file_p2pke_proto_rawDesc = nil
	file_p2pke_proto_goTypes = nil
	file_p2pke_proto_depIdxs = nil
}
